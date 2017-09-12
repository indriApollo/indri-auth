#!/usr/bin/env node

const fs = require("fs");

// load config.json
try {
    var confFile = fs.readFileSync("config.json","utf8");
    var config = JSON.parse(confFile);
}
catch(err) {
    console.log("Could not read configuration from config.json");
    console.log(err);
    return;
}

// set default if value was not set in config
function setVal(confKey, defaultValue) {
    var val;
    if(typeof config[confKey] !== "undefined")
        val = config[confKey];
    else
        val = defaultValue;

    if(confKey.match(/password/i))
        console.log("[config] "+confKey+" -> ********");
    else
        console.log("[config] "+confKey+" ->", val);
    return val;
}

const http = require('http'); // no https because we are behind a proxy
const zlib = require('zlib');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const nodemailer = require("nodemailer");
const urlHelper = require('url');

const dbops = require("./dbops.js");

const DB_NAME = setVal("DB_NAME", "indri-auth.db");
const SERVER_PORT = setVal("SERVER_PORT", 8000);

const INVALID_PASS_MS_DELAY = setVal("INVALID_PASS_MS_DELAY", 3000);
const TOKEN_BYTE_LENGTH = setVal("TOKEN_BYTE_LENGTH", 33); //264 bits, no base64 = padding
const TOKEN_VALIDITY_MS = setVal("TOKEN_VALIDITY_MS", 60 * 60 * 1000); // 1 hour
const GET_DEFAULT_RESPONSE = setVal("GET_DEFAULT_RESPONSE", {
    "message": "Welcome on the indri-auth service",
    "doc": "https://github.com/indriApollo/indri-auth"
});

const USERPASS_MIN_BYTELENGTH = setVal("USERPASS_MIN_BYTELENGTH", 12);
const BCRYPT_SALT_SIZE = setVal("BCRYPT_SALT_SIZE", 16);

const NODEMAILER_FROM = setVal("NODEMAILER_FROM", 'no-reply@indriapollo.be');
const NODEMAILER_SUBJECT = setVal("NODEMAILER_SUBJECT", "Password reset | %domain%");
const text = "You made a request for a new password on '%domain%'\r\nVisit this link to set a new password : %url%\r\n";
const NODEMAILER_TEXT = setVal("NODEMAILER_TEXT", text);

const smtp = nodemailer.createTransport({
    host: setVal("SMTP_SERVER", ""),
    port: setVal("SMTP_PORT", 587),
    secure: false, // upgrade later with STARTTLS
    auth: {
        user: setVal("SMTP_USER", ""),
        pass: setVal("SMTP_PASSWORD", "")
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
}).listen(SERVER_PORT);
console.log("server listening on port "+SERVER_PORT);

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

    dbRequestHandler(dbops.getUserHashFromDb, [username], function(err, uid, hash) {

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
                }, INVALID_PASS_MS_DELAY);
            }
            else
                deliverToken(uid);
        })
    }

    function deliverToken(uid) {
        var token = crypto.randomBytes(TOKEN_BYTE_LENGTH).toString("base64");
        var validity = Date.now() + TOKEN_VALIDITY_MS;

        dbRequestHandler(dbops.storeTokenInDb, ["tokens",uid,token,validity], function(err) {
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

    dbRequestHandler(dbops.getUserUidUsingUsernameFromDb, [email], function(err, uid) {
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
        dbRequestHandler(dbops.getTrustedUrlsFromDb, [domain], function(err, reseturi) {
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
        var token = crypto.randomBytes(TOKEN_BYTE_LENGTH).toString("base64");
        var validity = Date.now() + TOKEN_VALIDITY_MS;
        url+="#"+encodeURIComponent(token); // we encode to token to avoid problems with special chars in the url like +
    
        dbRequestHandler(dbops.storeTokenInDb, ["passreset",uid,token,validity], function(err) {
            if(err)
                respond(response, "Internal service error", 500);
            else
                sendPassResetEmail(url);                  
        });
    }

    function sendPassResetEmail(url) {
        console.log("Sending passreset to "+email);
        smtp.sendMail({
            from: NODEMAILER_FROM,
            to: email,
            subject: NODEMAILER_SUBJECT.replace(/%domain%/g, domain),
            text: NODEMAILER_TEXT.replace(/%domain%/g, domain).replace(/%url%/g, url)
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

    checkToken("passreset", token, false, function(err, valid, uid) {
        if(err) {
            console.log("Could not check passreset token");
            respond(response, "Internal service error", 500);
        }
        else if(!valid) {
            setTimeout(function () {
                respond(response, "Unknown or expired token", 403);
            }, INVALID_PASS_MS_DELAY);
        }
        else {
            checkPasswordFromJson(uid);
        }
    });

    function checkPasswordFromJson(uid) {
        var checkedJson = checkJson(json, ["password"]);
        if(checkedJson.error) {
            respond(response, checkedJson.error, 400);
            return;
        }
        var password = checkedJson.jsonData.password;

        if(typeof password !== 'string' || password.length < USERPASS_MIN_BYTELENGTH) {
            respond(response, "New password is invalid or too short", 400);
        }
        else
            nukeUsedResetToken(uid, password);
    }

    function nukeUsedResetToken(uid, password) {
        dbRequestHandler(dbops.storeTokenInDb, ["passreset", uid, "xxx", 0], function(err) {
            if(err) {
                console.log("Could not nuke used resetToken");
                respond(response, "Internal service error", 500);
            }
            else
                generateHash(uid, password);
        });
    }

    function generateHash(uid, password) {
        bcrypt.hash(password, BCRYPT_SALT_SIZE, function(err, hash) {
            if(err) {
                console.log("Could not generate bcrypt hash");
                respond(response, "Internal service error", 500);
            }
            else
                storeHash(uid, hash);
        });
    }

    function storeHash(uid, hash) {
        dbRequestHandler(dbops.storeUserHashInDb, [uid, hash], function(err) {
            if(err) {
                console.log("Could not store new user hash");
                respond(response, "Internal service error", 500);
            }
            else
                respond(response, "New password succesfully created", 201);
        });
    }
}

function handleGET(url, headers, body, response) {
    
    url = urlHelper.parse(url);
    var pathname = url.pathname;

    console.log("GET request for "+pathname);

    if(pathname == "/") {
        respond(response, GET_DEFAULT_RESPONSE, 200);
        return;
    }

    if(!headers["auth-token"]) {
        respond(response, "Missing Auth-Token header", 403);
        return;
    }
    var token = headers["auth-token"];

    checkToken("users", token, true, function(err, valid, uid) {
        if(err) {
            console.log("Could not check user token");
            respond(response, "Internal service error", 500);
        }
        else if(!valid) {
            setTimeout(function () {
                respond(response, "Unknown or expired token", 403);
            }, INVALID_PASS_MS_DELAY);
        }
        else {
            switch(pathname) {
                case "/userstatus":
                    response(response, "Authenticated", 200);
                    break;
                case "/userdata":
                    returnUserData(uid, response);
                    break;
                case "unauthenticate":
                    unauthUser(token, response);
                    break;
                default:
                    respond(response, "Unknown GET uri", 404);
            }
        }
    });
}

function unauthUser(token, response) {
    // Set the validity to zero. Checktoken will then always fail.
    dbRequestHandler(dbops.storeUserTokenValidityInDb, [token, 0], function(err) {
        if(err) {
            console.log("Could not unauthenticate user", err);
            respond(response, "Internal service error", 500);
        }
        else
            respond(reponse, "Goodbye", 200);
    });

}

function returnUserData(uid, response) {
    dbRequestHandler(dbops.getUserDataFromDb, [uid], function(err, userData) {
        if(err || !userData) {
            console.log("Could not fetch userdata");
            respond(response, "Internal service error", 500);
        }
        else
            respond(response, userData, 200);
    });
}

function checkToken(table, token, extendValidity, callback) {
    dbRequestHandler(dbops.getTokenValidityFromDb, [table,token], function(err, validity, uid) {
        if(err)
            callback(err);
        else if(!validity || (validity < Date.now()) )
            callback(null, false);
        else if(!extendValidity)
            callback(null, true, uid);
        else
            extendTokenValidity(uid);
    });

    function extendTokenValidity(uid) {
        var validity = Date.now() + TOKEN_VALIDITY_MS;
        dbRequestHandler(dbops.storeUserTokenValidityInDb, [token, validity], function(err) {
            if(err)
                callback(err);
            else
                callback(null, true, uid);
        });
    }
}

function dbRequestHandler(func, funcArgs, callback) {
    
    // We use a new db object for every transaction to assure isolation
    // See https://github.com/mapbox/node-sqlite3/issues/304
    var db = new sqlite3.Database(DB_NAME);
    func(db, ...funcArgs, function(cbArgs) { //note ... -> spread operator (I know, right?)
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
