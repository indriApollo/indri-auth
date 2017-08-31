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
    var buf = Buffer.from(JSON.stringify(data, null, 4), 'utf-8');
    
    response.statusCode = status;
    response.setHeader('Access-Control-Allow-Origin', '*');
    response.setHeader('Content-Encoding', 'gzip');
    response.setHeader('Content-Type', 'application/json');
    
    zlib.gzip(buf, function (_, result) {
        response.setHeader('Content-Length',result.length);
        response.end(result);
    });
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

function checkBcryptHash(pass, hash, callback) {
    bcrypt.compare(pass, hash, function(err, valid) {
        if(err) {
            console.log(err);
            callback("BCRYPT_ERROR");
        }
        else if(valid)
            callback("VALID");
        else
            callback("INVALID");
    })
}

function handlePOST(url, headers, body, response) {
    
    console.log("POST request for "+url);
    
    var matches = url.match(/^\/(authenticate|passreset(\/request)?)$/);
    if(!matches) {
        // Wrong uri -> complain
        respond(response, "Unknown POST uri", 404);
    }
    else if(matches[1] == "authenticate") {

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
    
        var checkedJson = checkJson(body, ["username","password"]);

        if(checkedJson.error) {
            respond(response, checkedJson.error, 400);
            return;
        }
        var username = checkedJson.jsonData.username;
        var password = checkedJson.jsonData.password;

        // first get hash from db
        dbRequestHandler(dbops.getUserHashFromDb, [username], function(err, uid, hash) {

            if(err) {
                respond(response, "Internal service error", 500);
                return;
            }
            if(!uid || !hash) {
                respond(response, "Unknown user "+username, 400);
                return;
            }
            // now check the hash
            checkBcryptHash(password, hash, function(r) {
                switch(r) {
                    case "BCRYPT_ERROR":
                        respond(response, "Internal service error", 500);
                        break;
                    case "INVALID":
                        setTimeout(function () {
                            respond(response, "Wrong password", 403);
                        }, INVALID_PASS_MS_DELAY);
                        break;
                    case "VALID":
                        // finally deliver the token
                        deliverToken(uid);
                        break;
                }
            });
        });
    }
    else if(matches[1] == "passreset/request") {
        
        function sendPassResetEmail(uid, email, domain, url) {
            var token = crypto.randomBytes(TOKEN_BYTE_LENGTH).toString("base64");
            console.log("reset token "+token);
            var validity = Date.now() + TOKEN_VALIDITY_MS;
        
            url+="#"+token;
        
            dbRequestHandler(dbops.storeTokenInDb, ["passreset",uid,token,validity], function(err) {
                if(err)
                    respond(response, "Internal service error", 500);
                else {
                    console.log("Sending passreset to "+email);
                    smtp.sendMail({
                        from: NODEMAILER_FROM,
                        to: email,
                        subject: NODEMAILER_SUBJECT.replace(/%domain%/g, domain),
                        text: NODEMAILER_TEXT.replace(/%domain%/g, domain).replace(/%url%/g, url)
                    }, function(err, info) {
                        console.log(info);
                        if(err) {
                            console.log("Could not send email");
                            console.log(err);
                            respond(response, "Internal service error", 500);
                        }
                        else if(!info.accepted || !info.accepted[0] == email) {
                            console.log(info);
                            respond(response, "Email was rejected", 500);
                        }
                        else
                            respond(response, {"message": "Email successfully sent"}, 200);
                    });
                }                    
            });
        }
        
        var checkedJson = checkJson(body, ["email","domain"]);
                
        if(checkedJson.error) {
            respond(response, checkedJson.error, 400);
            return;
        }
        var email = checkedJson.jsonData.email;
        var domain = checkedJson.jsonData.domain;
    
        checkUserExists(email, function(err, exists, uid) {
            if(err) {
                console.log("Could not check user's existence");
                respond(response, "Internal service error", 500);
            }
            else if(!exists)
                respond(response, "Unknown user", 400);
            else
                getPassResetUrl(domain, function(err, url) {
                    if(err) {
                        console.log("Could not get pass reset url");
                        respond(response, "Internal service error", 500);
                    }
                    else if(!url)
                        respond(response, "Unknown domain", 400);
                    else
                        sendPassResetEmail(uid, email, domain, url);
                });
        });
    }
    else if(matches[1] == "passreset") {
        if(!headers["auth-token"]) {
            respond(response, "Missing Auth-Token header", 400);
            return;
        }
        var token = headers["auth-token"];

        checkToken("passreset", token, function(err, valid, uid) {
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
                var checkedJson = checkJson(body, ["password"]);
                if(checkedJson.error) {
                    respond(response, checkedJson.error, 400);
                    return;
                }
                var password = checkedJson.jsonData.password;

                if(typeof password !== 'string' || password.length < USERPASS_MIN_BYTELENGTH) {
                    respond(response, "New password is invalid or too short", 400);
                }
                console.log("gonna salt");
                bcrypt.hash(password, BCRYPT_SALT_SIZE, function(err, hash) {
                    if(err) {
                        console.log("Could not generate bcrypt hash");
                        respond(response, "Internal service error", 500);
                    }
                    else {
                        console.log("gonna store");
                        dbRequestHandler(dbops.storeUserHashInDb, [uid, hash], function(err) {
                            if(err) {
                                console.log("Could not store new user hash");
                                respond(response, "Internal service error", 500);
                            }
                            else
                                respond(response, "New password succesfully created", 201);
                        });
                    }
                });
            }
        });
    }
}

function handleGET(url, headers, body, response) {
    
    console.log("GET request for "+url);
    
    var matches = url.match(/^\/(userdata)$/);
    if(!matches) {
        respond(response, GET_DEFAULT_RESPONSE, 200);
    }
    else if(matches[1] == "userdata") {
        if(!headers["auth-token"]) {
            respond(response, "Missing Auth-Token header", 400);
            return;
        }
        var token = headers["auth-token"];

        checkToken("tokens", token, function(err, valid, uid) {

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
                dbRequestHandler(dbops.getUserDataFromDb, [uid], function(err, userData) {
                    if(err || !userData) {
                        console.log("Could not fetch userdata");
                        respond(response, "Internal service error", 500);
                    }
                    else
                        respond(response, userData, 200);
                });
            }
        });
    }
}

function checkToken(table, token, callback) {
    dbRequestHandler(dbops.getTokenValidityFromDb, [table,token], function(err, validity, uid) {
        if(err)
            callback(err);
        else if(!validity || (validity < Date.now()) )
            callback(null, false);
        else
            callback(null, true, uid);
    });
}

function checkUserExists(username, callback) {
    dbRequestHandler(dbops.getUserUidFromDb, [username], function(err, uid) {
        if(err)
            callback(err);
        else if(!uid)
            callback(null, false);
        else
            callback(null, true, uid);
    });
}

function getPassResetUrl(domain, callback) {
    dbRequestHandler(dbops.getTrustedUrlsFromDb, [domain], function(err, reseturi) {
        if(err)
            callback(err);
        else if(!reseturi)
            callback(null, null);
        else
            callback(null, "https://"+domain+reseturi);
    });
}
