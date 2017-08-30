#!/usr/bin/env node

const http = require('http'); // no https because we are behind a proxy
const zlib = require('zlib');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const DB_NAME = "indri-auth.db";
const PORT = 8000;

const INVALID_PASS_MS_DELAY = 3000;
const TOKEN_BYTE_LENGTH = 33; //264 bits, no base64 = padding
const TOKEN_VALIDITY_MS = 60 * 60 * 1000; // 1 hour
const GET_DEFAULT_RESPONSE = {
    "message": "Welcome on the indri-auth service",
    "doc": "https://"
}

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
}).listen(PORT);
console.log("server listening on "+PORT);

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
    
    // http 200 reponses already have json data
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
        r.error = err;
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
    
    var matches = url.match(/^\/authenticate$/);
    if(matches) {

        function deliverToken(uid) {
            var token = crypto.randomBytes(TOKEN_BYTE_LENGTH).toString("base64");
            var validity = Date.now() + TOKEN_VALIDITY_MS;
            dbRequestHandler(storeUserTokenInDb, [uid,token,validity], function(err) {
                if(err) {
                    respond(response, "Internal service error", 500);
                } else {
                    respond(response, {'token': token}, 200);
                }
            })
        }
    
        var checkedJson = checkJson(body, ["username","password"]);

        if(checkedJson.error) {
            respond(response, checkedJson.error, 400);
            return;
        }
        var username = checkedJson.jsonData.username;
        var password = checkedJson.jsonData.password;

        // first get hash from db
        dbRequestHandler(getUserHashFromDb, [username], function(err, uid, hash) {

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
    // Wrong uri -> complain
    else
        respond(response, "Unknown POST uri", 404);
}
    
function getUserHashFromDb(db, username, callback) {
    db.get("SELECT uid, hash FROM users WHERE username = ?", username, function(err, row) {
        if(err) {
            console.log(err);
            callback([err]);
        }
        else if(!row)
            callback([]);
        else
            callback([null, row.uid, row.hash]);
    });
}

function storeUserTokenInDb(db, uid, token, validity, callback) {
    db.run("UPDATE tokens SET token = ?, validity = ? WHERE uid = ?", token, validity, uid, function(err) {
        if(err) console.log(err);
        callback([err]);
    })
}

function handleGET(url, headers, body, response) {
    
    console.log("GET request for "+url);
    
    var matches = url.match(/^\/userdata$/);
    if(matches) {
        if(!headers["auth-token"]) {
            respond(response, "Missing Auth-Token header", 400);
            return;
        }
        var token = headers["auth-token"];

        checkToken(token, function(err, valid, uid) {

            if(err) {
                console.log("Could not check token");
                respond(response, "Internal service error", 500);
            }
            else if(!valid) {
                setTimeout(function () {
                    respond(response, "Unknown or expired token", 403);
                }, INVALID_PASS_MS_DELAY);
            }
            else {
                dbRequestHandler(getUserDataFromDb, [uid], function(err, userData) {
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
    else
        respond(response, GET_DEFAULT_RESPONSE, 200);
}

function checkToken(token, callback) {
    dbRequestHandler(getTokenValidityFromDb, [token], function(err, validity, uid) {
        if(err)
            callback(err);
        else if(!validity || (validity < Date.now()) )
            callback(null, false);
        else
            callback(null, true, uid);
    });
}

function getTokenValidityFromDb(db, token, callback) {
    db.get("SELECT uid,validity FROM tokens WHERE token = ?", token, function(err, row) {
        if(err) {
            console.log(err);
            callback([err]);
        }
        else if(!row)
            callback([]);
        else 
            callback([null, row.validity, row.uid]);
    });
}

function getUserDataFromDb(db, uid, callback) {
    db.get("SELECT userdata FROM usersdata WHERE uid = ?", uid, function(err, row) {
        if(err) {
            console.log(err);
            callback([err]);
        }
        else if(!row)
            callback([]);
        else
            callback([null, row.userdata]);
    });
}
