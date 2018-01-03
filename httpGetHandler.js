const cm = require("./common.js");
const Db = require("./db.js");

function Handler(conf, pathname, response) {
    this.conf = conf;
    this.pathname = pathname;
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

Handler.prototype.returnHomepage = function() {
    this.respond(this.conf.get("GET_DEFAULT_RESPONSE"), 200);
}

Handler.prototype.returnUserStatus = function() {
    // GET userstatus

    if(this.isAdmin)
        this.respond({"status": "admin"}, 200);
    else
        this.respond({"status": "authenticated"}, 200);
}

Handler.prototype.returnAllUsers = function() {
    // GET users
    var handler = this;
    
    if(!handler.isAdmin) {
        handler.respond("You do not have access to this", 403);
        return;
    }

    handler.db.getAllUsersFromDb(function(err, users) {
        if(err) {
            console.log("Could not get all users", err);
            handler.respond("Internal service error", 500);
        }
        else
            handler.respond({"users": users}, 200);
    });
}

Handler.prototype.unauthUser = function(token) {
    // GET unauthenticate
    var handler = this;

    // Set the validity to zero. Checktoken will then always fail.
    handler.db.storeUserTokenValidityInDb(token, 0, function(err) {
        if(err) {
            console.log("Could not unauthenticate user", err);
            handler.respond("Internal service error", 500);
        }
        else
            handler.respond({"message": "Goodbye"}, 200);
    });

}

Handler.prototype.returnOwnUserData = function(uid) {
    // GET userdata
    var handler = this;

    handler.db.getUserDataUsingUidFromDb(uid, function(err, userData) {
        if(err || !userData) {
            console.log("Could not fetch userdata");
            handler.respond("Internal service error", 500);
        }
        else
            handler.respond(userData, 200);
    });
}

Handler.prototype.returnUserDataForUserName = function(username) {
    // GET userdata/<username>
    var handler = this;

    console.log("return userdata for", username);

    handler.db.getUserDataUsingUsernameFromDb(username, function(err, userData) {
        if(err) {
            console.log("Could not fetch userdata");
            handler.respond("Internal service error", 500);
        }
        else if(!userData)
            handler.respond("Unknown user", 400);
        else
            handler.respond(userData, 200);
    });
}

Handler.prototype.returnUserData = function(uid) {
    
    var p = this.pathname.split("/");
    var username = p[2];

    if(this.pathname == "/userdata") {
        this.returnOwnUserData(uid);
    }
    else if(this.isAdmin) {
        if(!username)
            this.respond("Missing username", 400);
        else
            this.returnUserDataForUserName(username);
    }
    else
        this.respond("You do not have access to this", 403);
}

function httpGetHandler(conf, pathname, headers, response) {

    console.log("GET request for", pathname);

    var handler = new Handler(conf, pathname, response);

    if(pathname == "/") {
        handler.returnHomepage();
        return;
    }

    handler.openDb();
    cm.checkToken(handler, headers, "tokens", true, function(err, uid, token) {
        
        if(err)
            handler.respond("Internal service error", 500);
        else if(!uid)
            handler.respond("Unknown or expired token", 403);
        else {
            cm.userStatus(handler, uid, function(err) {
                if(err)
                    handler.respond("Internal service error", 500);
                else
                    routes(uid, token);
            });
        }
    });

    function routes(uid, token) {

        /*
         * /userdata
         * /userdata/<username> (admin)
         * 
         * /userstatus
         * 
         * /unauthenticate
         * 
         * /users (admin)
         * 
         */

        if(/^\/userdata(\/[\w.@]*)?$/.test(pathname) )
            handler.returnUserData(uid);
        
        else if(pathname == "/userstatus")
            handler.returnUserStatus();
                
        else if(pathname == "/unauthenticate")
            handler.unauthUser(token);
            
        else if(pathname == "/users")
            handler.returnAllUsers();

        else
            handler.respond("Unknown GET uri", 404);

    }
}

module.exports = httpGetHandler;
