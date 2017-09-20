#!/usr/bin/env node

const http = require('http'); // no https because we are behind a proxy
const zlib = require('zlib');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const nodemailer = require("nodemailer");
const urlHelper = require('url');

const dbops = require("./dbops.js");
const conf = require("./configloader.js");

console.log("Loading config ...");
conf.load();

const smtp = nodemailer.createTransport({
    host: conf.get("SMTP_SERVER"),
    port: conf.get("SMTP_PORT"),
    secure: false, // upgrade later with STARTTLS
    auth: {
        user: conf.get("SMTP_USER"),
        pass: conf.get("SMTP_PASSWORD")
    }
});

http.createServer(function(request, response) {
    
    var headers = request.headers;
    var method = request.method;
    var url = request.url;
    var body = [];
    
    response.on('error', function(err) {
        console.error(err);
    });
    
    request.on('error', function(err) {
        console.error(err);
        response.statusCode = 500;
        response.end();
    
    }).on('data', function(chunk) {
        body.push(chunk);
    }).on('end', function() {
        body = Buffer.concat(body).toString();
    
        switch(method) {
            case 'GET':
                handleGET(url, headers, body, response);
                break;
    
            case 'POST':
                handlePOST(url, headers, body, response);
                break;
    
            case 'OPTIONS':
                handleCORS(response);
                break;
    
            default:
                respond(response, "Unsupported http method", 400);
                break;
        }
    });
}).listen(conf.get("SERVER_PORT"));
console.log("server listening on port "+conf.get("SERVER_PORT"));

function handleCORS(response) {
    
    /*
     * Handle Cross-Origin Resource Sharing (CORS)
     *
     * See : https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Preflighted_requests
     */
        
    // The preflighted requests expects http 200 for a successful request
    response.statusCode = 200;
    // We allow requests from any origin
    response.setHeader('Access-Control-Allow-Origin', '*');
    // We have to explicitly allow Auth-Token since it's a custom header
    response.setHeader('Access-Control-Allow-Headers', 'Auth-Token,User-Agent,Content-Type'); //can't use * !
    // We allow POST, GET and OPTIONS http methods
    response.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    response.end();
}

function respond(response, data, status) {
    
    // http 200 responses already have json data
    // Other status codes are using a simple json message: <msg> format
    if(status != 200)
        data = { message: data};
    
    // We pretty print the json data and store it in  an utf-8 buffer
    // Storing it in a buffer means that we can easily gzip it later
    if(typeof data !== 'string') data = JSON.stringify(data, null, 4);
    var buf = Buffer.from(data, 'utf-8');
    
    response.setHeader('Access-Control-Allow-Origin', '*');

    zlib.gzip(buf, function (err, result) {
        if(err) {
            console.log("Could not gzip response", err);
            response.statusCode = 500;
            response.end();
        }
        else {
            response.statusCode = status;
            response.setHeader('Content-Encoding', 'gzip');
            response.setHeader('Content-Type', 'application/json');
            response.setHeader('Content-Length',result.length);
            response.end(result);
        }
    });
}

function handlePOST(url, headers, body, response) {
    
    url = urlHelper.parse(url);
    var pathname = url.pathname;

    console.log("POST request for "+pathname);


    if(/^\/userdata\/[\w%.@]*$/.test(pathname)) {
        saveNewUserdata(response, pathname, headers, body);
        return;
    }

    switch(pathname) {
        case "/authenticate":
            handleAuthentication(body, response);
            break;
        case "/passreset/request":
            // user asked for a reset email
            handlePassResetRequest(body, response);
            break;
        case "/passreset":
            saveNewUserPassword(headers, body, response);
            break;
        default:
            respond(response, "Unknown POST uri", 404);
            break;
    }
}

function handleAuthentication(json, response) {

    var checkedJson = checkJson(json, ["username","password"]);

    if(checkedJson.error) {
        respond(response, checkedJson.error, 400);
        return;
    }
    var username = checkedJson.jsonData.username;
    var password = checkedJson.jsonData.password;

    dbRequestHandler(dbops.getUserHashFromDb, username, function(err, uid, hash) {

        if(err)
            respond(response, "Internal service error", 500);
        if(!uid || !hash)
            respond(response, "Unknown user "+username, 403);
        else 
            checkBcryptHash(uid , hash);
    });

    function checkBcryptHash(uid , hash) {
        bcrypt.compare(password, hash, function(err, valid) {
            if(err) {
                console.log("Could not check bcrypt hash", err);
                respond(response, "Internal service error", 500);
            }
            else if(!valid){
                setTimeout(function () {
                    respond(response, "Wrong password", 403);
                }, conf.get("INVALID_PASS_MS_DELAY"));
            }
            else
                deliverToken(uid);
        })
    }

    function deliverToken(uid) {
        var token = crypto.randomBytes(conf.get("TOKEN_BYTE_LENGTH")).toString("base64");
        var validity = Date.now() + conf.get("TOKEN_VALIDITY_MS");

        dbRequestHandler(dbops.storeTokenInDb, "tokens", uid, token, validity, function(err) {
            if(err)
                respond(response, "Internal service error", 500);
            else
                respond(response, {'token': token}, 200);
        });
    }
}

function handlePassResetRequest(json, response) {
    
    var checkedJson = checkJson(json, ["email","domain"]);
            
    if(checkedJson.error) {
        respond(response, checkedJson.error, 400);
        return;
    }
    var email = checkedJson.jsonData.email;
    var domain = checkedJson.jsonData.domain;

    dbRequestHandler(dbops.getUserUidUsingUsernameFromDb, email, function(err, uid) {
        if(err) {
            console.log("Could not check user's existence");
            respond(response, "Internal service error", 500);
        }
        else if(!uid)
            respond(response, "Unknown user", 400);
        else
            getPassResetUrl(uid);
    });

    function getPassResetUrl(uid) {
        dbRequestHandler(dbops.getTrustedUrlsFromDb, domain, function(err, reseturi) {
            if(err) {
                console.log("Could not get pass reset url");
                respond(response, "Internal service error", 500);
            }
            else if(!reseturi)
                respond(response, "Unknown domain", 400);
            else
                generatePassResetToken(uid, "https://"+domain+reseturi);
        });

    }

    function generatePassResetToken(uid, url) {
        var token = crypto.randomBytes(conf.get("TOKEN_BYTE_LENGTH")).toString("base64");
        var validity = Date.now() + TOKEN_VALIDITY_MS;
        url+="#"+encodeURIComponent(token); // we encode to token to avoid problems with special chars in the url like +
    
        dbRequestHandler(dbops.storeTokenInDb, "passreset", uid, token, validity, function(err) {
            if(err)
                respond(response, "Internal service error", 500);
            else
                sendPassResetEmail(url);                  
        });
    }

    function sendPassResetEmail(url) {
        console.log("Sending passreset to "+email);
        smtp.sendMail({
            from: conf.get("NODEMAILER_FROM"),
            to: email,
            subject: conf.get("NODEMAILER_SUBJECT").replace(/%domain%/g, domain),
            text: conf.get("NODEMAILER_TEXT").replace(/%domain%/g, domain).replace(/%url%/g, url)
        }, function(err, info) {
            if(err) {
                console.log("Could not send email", err);
                respond(response, "Internal service error", 500);
            }
            else if(!info.accepted || !info.accepted[0] == email) {
                console.log("Email was rejected", info);
                respond(response, "Email was rejected", 500);
            }
            else
                respond(response, {"message": "Email successfully sent"}, 200);
        });
    }
}

function saveNewUserPassword(headers, json, response) {

    if(!headers["auth-token"]) {
        respond(response, "Missing Auth-Token header", 403);
        return;
    }
    var token = headers["auth-token"];

    checkToken(response, "passreset", token, false, checkPasswordFromJson(uid) );

    function checkPasswordFromJson(uid) {
        var checkedJson = checkJson(json, ["password"]);
        if(checkedJson.error) {
            respond(response, checkedJson.error, 400);
            return;
        }
        var password = checkedJson.jsonData.password;

        if(typeof password !== 'string' || password.length < conf.get("USERPASS_MIN_BYTELENGTH")) {
            respond(response, "New password is invalid or too short", 400);
        }
        else
            nukeUsedResetToken(uid, password);
    }

    function nukeUsedResetToken(uid, password) {
        dbRequestHandler(dbops.storeTokenInDb, "passreset", uid, "xxx", 0, function(err) {
            if(err) {
                console.log("Could not nuke used resetToken");
                respond(response, "Internal service error", 500);
            }
            else
                generateHash(uid, password);
        });
    }

    function generateHash(uid, password) {
        bcrypt.hash(password, conf.get("BCRYPT_SALT_SIZE"), function(err, hash) {
            if(err) {
                console.log("Could not generate bcrypt hash");
                respond(response, "Internal service error", 500);
            }
            else
                storeHash(uid, hash);
        });
    }

    function storeHash(uid, hash) {
        dbRequestHandler(dbops.storeUserHashInDb, uid, hash, function(err) {
            if(err) {
                console.log("Could not store new user hash");
                respond(response, "Internal service error", 500);
            }
            else
                respond(response, "New password succesfully created", 201);
        });
    }
}

function saveNewUserdata(response, pathname, headers, body) {

    if(!headers["auth-token"]) {
        respond(response, "Missing Auth-Token header", 403);
        return;
    }
    var token = headers["auth-token"];

    checkToken(response, "tokens", token, true, function(uid) {
        checkIsAdmin(response, uid, checkUserExists);
    });

    function checkUserExists() {

        var m = /^\/userdata\/([\w%.@]*)$/.exec(pathname);

        dbRequestHandler(dbops.getUserUidUsingUsernameFromDb, m[1], function(err, userId) {
            if(err) {
                console.log("Could not check admin status", err);
                respond(response, "Internal service error", 500);
            }
            else if(!userId)
                respond(response,"Unknown user", 400);
            else
                storeUserdata(userId);
        });
    }

    function storeUserdata() {
        try {
            var userdata = JSON.parse(body);
            if(!userdata.instruments)
                throw "Missing instruments property";
            
            userdata = JSON.stringify(userdata);
        }
        catch(err) {
            console.log("Userdata validation error", err);
            respond(response, "Invalid userdata json", 400);
            return;
        }
        dbRequestHandler(dbops.storeUserDataInDb, userId, userdata, function(err) {
            if(err) {
                console.log("Could not save new userdata", err);
                respond(response, "Internal service error", 500);
            }
            else
                respond(reponse, "Saved", 201);
        });
    }
}

function handleGET(url, headers, body, response) {
    
    url = urlHelper.parse(url);
    var pathname = url.pathname;

    console.log("GET request for "+pathname);

    if(pathname == "/") {
        respond(response, conf.get("GET_DEFAULT_RESPONSE"), 200);
        return;
    }

    if(!headers["auth-token"]) {
        respond(response, "Missing Auth-Token header", 403);
        return;
    }
    var token = headers["auth-token"];

    checkToken(response, "tokens", token, true, function(uid) {
        
        if(/^\/userdata(\/[\w%.@]*)?$/.test(pathname)) {
            returnUserData(uid, pathname, response);
            return;
        }
        
        switch(pathname) {
            case "/userstatus":
                returnUserStatus(uid, response);
                break;
            case "/unauthenticate":
                unauthUser(token, response);
                break;
            case "/users":
                returnAllUsers(uid, response);
                break;
            default:
                respond(response, "Unknown GET uri", 404);
                break;
        }
    });
}

function returnUserStatus(uid, response) {
    dbRequestHandler(dbops.getAdminStatusFromDb, uid, function(err, isAdmin) {
        if(err) {
            console.log("Could not check admin status", err);
            respond(response, "Internal service error", 500);
        }
        else if(isAdmin != 1)
            respond(response, {'status': 'authenticated'}, 200);
        else
            respond(response, {'status': 'admin'}, 200);
    });
}

function returnAllUsers(uid, response) {
    dbRequestHandler(dbops.getAdminStatusFromDb, uid, function(err, isAdmin) {
        if(err) {
            console.log("Could not check admin status", err);
            respond(response, "Internal service error", 500);
        }
        else if(isAdmin != 1)
            respond(response, "You do not have access to this", 403);
        else
            getAllUsers();
    });

    function getAllUsers() {
        dbRequestHandler(dbops.getAllUsersFromDb, null, function(err, users) {
            if(err) {
                console.log("Could not get all users", err);
                respond(response, "Internal service error", 500);
            }
            else
                respond(response, {'users': users}, 200);
        });
    }
}

function unauthUser(token, response) {
    // Set the validity to zero. Checktoken will then always fail.
    dbRequestHandler(dbops.storeUserTokenValidityInDb, token, 0, function(err) {
        if(err) {
            console.log("Could not unauthenticate user", err);
            respond(response, "Internal service error", 500);
        }
        else
            respond(response, "Goodbye", 200);
    });

}

function returnUserData(uid, pathname, response) {
    
    var m = /^\/userdata(\/[\w%.@]*)?$/.exec(pathname);

    if(!m[1]) {
        dbRequestHandler(dbops.getUserDataUsingUidFromDb, uid, function(err, userData) {
            if(err || !userData) {
                console.log("Could not fetch userdata");
                respond(response, "Internal service error", 500);
            }
            else
                respond(response, userData, 200);
        });
    }
    else
        checkIsAdmin(response, uid, returnUserDataUsingusername);

    function returnUserDataUsingusername() {

        var username = m[1].substr(1);
        console.log("return userdata for "+username);

        dbRequestHandler(dbops.getUserDataUsingUsernameFromDb, username, function(err, userData) {
            if(err) {
                console.log("Could not fetch userdata");
                respond(response, "Internal service error", 500);
            }
            else if(!userData)
                respond(response, "Unknown user", 400);
            else
                respond(response, userData, 200);
        });
    }
}

function checkToken(response, table, token, extendValidity, callback) {

    dbRequestHandler(dbops.getTokenValidityFromDb, table, token, function(err, validity, uid) {
        if(err) {
            console.log("Could not check token from", table);
            respond(response, "Internal service error", 500);
        }
        else if( !validity || ( validity < Date.now() ) ) {
            setTimeout(function () {
                respond(response, "Unknown or expired token", 403);
            }, conf.get(INVALID_PASS_MS_DELAY));
        }
        else if(!extendTokenValidity)
            callback(uid);
        else
            extendTokenValidity(uid);
    });

    function extendTokenValidity(uid) {
        var validity = Date.now() + conf.get("TOKEN_VALIDITY_MS");
        dbRequestHandler(dbops.storeUserTokenValidityInDb, token, validity, function(err) {
            if(err) {
                console.log("Could not extend token from", table);
                respond(response, "Internal service error", 500);
            }
            else
                callback(uid);
        });
    }
}

function checkIsAdmin(response, uid, callback) {
    dbRequestHandler(dbops.getAdminStatusFromDb, uid, function(err, isAdmin) {
        if(err) {
            console.log("Could not check admin status", err);
            respond(response, "Internal service error", 500);
        }
        else if(isAdmin != 1)
            respond(response, "You don't have access to this", 403);
        else
            callback();
    });
}

function dbRequestHandler(func, ...funcArgs) {
    const callback = funcArgs.pop(); // last arg should be callback
    // We use a new db object for every transaction to assure isolation
    // See https://github.com/mapbox/node-sqlite3/issues/304
    var db = new sqlite3.Database(conf.get("DB_NAME"));
    db.configure("busyTimeout", conf.get("BUSY_TIMEOUT"));
    func(db, ...funcArgs, function(...cbArgs) { //note ... -> spread operator (I know, right?)
        db.close();
        callback(...cbArgs);
    });
}

function checkJson(jsonString, pnames) {
    var r = {};
    try {
        r.jsonData = JSON.parse(jsonString);

        for(var i = 0; i < pnames.length; i++) {
            var property = pnames[i];
            if(!r.jsonData.hasOwnProperty(property))
                throw "Missing or invalid "+property+" property";
        }
    }
    catch(err) {
        console.log(err);
        r.error = "Invalid json";
    }
    return r;
}
