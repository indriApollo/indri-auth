const cm = require("./common.js");
const Db = require("./db.js");
const zlib = require("zlib");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

function Handler(conf, pathname, headers, body, smtp, response) {
    this.conf = conf;
    this.pathname = pathname;
    this.headers = headers;
    this.body = body;
    this.smtp = smtp;
    this.response = response;
    this.db = null;
    this.isAdmin = false;
}

Handler.prototype.openDb = function() {
    this.db = new Db(this.conf.get("DB_NAME"), this.conf.get("BUSY_TIMEOUT"));
}

Handler.prototype.respond = function(data, status) {
    if(this.db)
        this.db.close();
    cm.respond(this.response, data, status);
}

Handler.prototype.authenticate = function() {
    // POST authenticate {username: string, password: string}
    var handler = this;

    var checkedJson = cm.checkJson(handler.body, ["username","password"]);

    if(checkedJson.error) {
        handler.respond(checkedJson.error, 400);
        return;
    }
    var username = checkedJson.jsonData.username;
    var password = checkedJson.jsonData.password;

    handler.openDb();
    handler.db.getUserHashFromDb(username, function(err, uid, hash) {

        if(err)
            handler.respond("Internal service error", 500);
        if(!uid || !hash)
            handler.respond("Unknown user "+username, 403);
        else 
            checkBcryptHash(uid , hash);
    });

    function checkBcryptHash(uid , hash) {
        bcrypt.compare(password, hash, function(err, valid) {
            if(err) {
                console.log("Could not check bcrypt hash", err);
                handler.respond("Internal service error", 500);
            }
            else if(!valid){
                setTimeout(function () {
                    handler.respond("Wrong password", 403);
                }, handler.conf.get("INVALID_PASS_MS_DELAY"));
            }
            else
                deliverToken(uid);
        })
    }

    function deliverToken(uid) {
        var token = crypto.randomBytes(handler.conf.get("TOKEN_BYTE_LENGTH")).toString("base64");
        var validity = Date.now() + handler.conf.get("TOKEN_VALIDITY_MS");

        handler.db.storeTokenInDb("tokens", uid, token, validity, function(err) {
            if(err)
                handler.respond("Internal service error", 500);
            else
                handler.respond({"token": token}, 200);
        });
    }
}

Handler.prototype.passResetRequest = function() {
    //POST passreset/request {email: string, domain: string}
    var handler = this;

    var checkedJson = cm.checkJson(handler.body, ["email","domain"]);
            
    if(checkedJson.error) {
        handler.respond(checkedJson.error, 400);
        return;
    }
    var email = checkedJson.jsonData.email;
    var domain = checkedJson.jsonData.domain;

    handler.openDb();
    handler.db.getUserUidUsingUsernameFromDb(email, function(err, uid) {
        if(err) {
            console.log("Could not check user's existence");
            handler.respond("Internal service error", 500);
        }
        else if(!uid)
            handler.respond("Unknown user", 400);
        else
            getPassResetUrl(uid);
    });

    function getPassResetUrl(uid) {
        handler.db.getTrustedUrlsFromDb(domain, function(err, reseturi) {
            if(err) {
                console.log("Could not get pass reset url");
                handler.respond("Internal service error", 500);
            }
            else if(!reseturi)
                handler.respond("Unknown domain", 400);
            else
                generatePassResetToken(uid, "https://"+domain+reseturi);
        });

    }

    function generatePassResetToken(uid, url) {
        var token = crypto.randomBytes(handler.conf.get("TOKEN_BYTE_LENGTH")).toString("base64");
        var validity = Date.now() + handler.conf.get("TOKEN_VALIDITY_MS");
        
        url += "#"+encodeURIComponent(token); // we encode to token to avoid problems with special chars in the url like +
    
        handler.db.storeTokenInDb("passreset", uid, token, validity, function(err) {
            if(err)
                handler.respond("Internal service error", 500);
            else
                sendPassResetEmail(url);
        });
    }

    function sendPassResetEmail(url) {

        console.log("Sending passreset to", email);
        
        handler.smtp.sendMail({
            from: handler.conf.get("NODEMAILER_FROM"),
            to: email,
            subject: handler.conf.get("NODEMAILER_SUBJECT").replace(/%domain%/g, domain),
            text: handler.conf.get("NODEMAILER_TEXT").replace(/%domain%/g, domain).replace(/%url%/g, url)
        }, function(err, info) {
            if(err) {
                console.log("Could not send email", err);
                handler.respond("Internal service error", 500);
            }
            else if(!info.accepted || !info.accepted[0] == email) {
                console.log("Email was rejected", info);
                handler.respond("Email was rejected", 500);
            }
            else
                handler.respond({"message": "Email successfully sent"}, 200);
        });
    }
}

Handler.prototype.saveNewUserPassword = function() {
    //POST passreset {password: string}
    var handler = this;

    handler.openDb();
    cm.checkToken(handler, handler.headers, "passreset", false, function (err, uid, token) {

        if(err)
            handler.respond("Internal service error", 500);
        else if(!uid)
            handler.respond("Unknown or expired token", 403);
        else
            checkNewPassword(uid);
    });

    function checkNewPassword(uid) {
        var checkedJson = cm.checkJson(handler.body, ["password"]);
        if(checkedJson.error) {
            handler.respond(checkedJson.error, 400);
            return;
        }
        var password = checkedJson.jsonData.password;

        if(typeof password !== "string" || password.length < handler.conf.get("USERPASS_MIN_BYTELENGTH")) {
            handler.respond("New password is invalid or too short", 400);
        }
        else
            nukeUsedResetToken(uid, password);
    }

    function nukeUsedResetToken(uid, password) {
        handler.db.storeTokenInDb("passreset", uid, "xxx", 0, function(err) {
            if(err) {
                console.log("Could not nuke used resetToken");
                handler.respond("Internal service error", 500);
            }
            else
                generateHash(uid, password);
        });
    }

    function generateHash(uid, password) {
        bcrypt.hash(password, handler.conf.get("BCRYPT_SALT_SIZE"), function(err, hash) {
            if(err) {
                console.log("Could not generate bcrypt hash");
                handler.respond("Internal service error", 500);
            }
            else
                storeHash(uid, hash);
        });
    }

    function storeHash(uid, hash) {
        handler.db.storeUserHashInDb(uid, hash, function(err) {
            if(err) {
                console.log("Could not store new user hash");
                handler.respond("Internal service error", 500);
            }
            else
                handler.respond({"message": "New password succesfully created"}, 201);
        });
    }
}

Handler.prototype.saveNewUserdata = function() {
    // POST userdata/<username> {userdata: [ instruments ]}
    var handler = this;

    var p = handler.pathname.split("/");
    var username = p[2];

    handler.openDb();
    cm.checkToken(handler, handler.headers, "tokens", true, function(err, uid, token) {
        if(err)
            handler.respond("Internal service error", 500);
        else if(!uid)
            handler.respond("Unknown or expired token", 403);
        else {
            cm.userStatus(handler, uid, function(err) {
                if(err)
                    handler.respond("Internal service error", 500);
                else if(!handler.isAdmin)
                    handler.respond("You have to be admin", 403);
                else
                    checkUserExists();
            });
        }
    });

    function checkUserExists() {

        handler.db.getUserUidUsingUsernameFromDb(username, function(err, userId) {
            if(err) {
                console.log("Could not check admin status");
                handler.respond("Internal service error", 500);
            }
            else if(!userId)
                handler.respond("Unknown user", 400);
            else
                storeUserdata(userId);
        });
    }

    function storeUserdata(userId) {
        var checkedJson = cm.checkJson(handler.body, ["instruments"]);
        if(checkedJson.error) {
            handler.respond(checkedJson.error, 400);
            return;
        }

        handler.db.storeUserDataInDb(userId, JSON.stringify(checkedJson.jsonData), function(err) {
            if(err) {
                console.log("Could not save new userdata");
                handler.respond("Internal service error", 500);
            }
            else
                handler.respond({"message": "Saved"}, 201);
        });
    }
}

function httpPostHandler(conf, pathname, headers, body, smtp, response) {

    console.log("POST request for", pathname);

    var handler = new Handler(conf, pathname, headers, body, smtp, response);

    /*
     * /userdata/<username> (admin)
     * 
     * /authenticate
     * 
     * /passreset
     * /passreset/request
     * 
     */

    if(/^\/userdata\/[\w.@]*$/.test(pathname) )
        handler.saveNewUserdata();
        
    else if(pathname == "/authenticate")
        handler.authenticate();

    else if(pathname == "/passreset")
        handler.saveNewUserPassword();

    else if(pathname == "/passreset/request")
        handler.passResetRequest();

    else
        handler.respond("Unknown POST uri", 404);

}

module.exports = httpPostHandler;
