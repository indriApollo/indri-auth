const zlib = require("zlib");

module.exports = {
    
    respond: function(response, data, status) {
    
        // http 200 - 201 responses already have json data
        // Other status codes are using a simple json message: <msg> format
        if(status != 200 && status != 201)
            data = {"message": data};
        
        // We pretty print the json data and store it in  an utf-8 buffer
        // Storing it in a buffer means that we can easily gzip it later
        if(typeof data !== "string") data = JSON.stringify(data, null, 4);
        var buf = Buffer.from(data, "utf-8");
        
        response.setHeader("Access-Control-Allow-Origin", "*");
        
        zlib.gzip(buf, function (err, result) {
            if(err) {
                console.log("Could not gzip response", err);
                response.statusCode = 500;
                response.end();
            }
            else {
                response.statusCode = status;
                response.setHeader("Content-Encoding", "gzip");
                response.setHeader("Content-Type", "application/json");
                response.setHeader("Content-Length",result.length);
                response.end(result);
            }
        });
    },

    checkJson: function(jsonString, pnames) {
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
    },

    checkToken: function(handler, headers, table, extendValidity, callback) {

        if(!headers["auth-token"]) {
            callback(null, false);
            return;
        }
        var token = headers["auth-token"];

        handler.db.getTokenValidityFromDb(table, token, function(err, validity, uid) {
            if(err) {
                console.log("Could not check token from", table);
                callback(err);
            }
            else if( !validity || ( validity < Date.now() ) ) {
                setTimeout(function () {
                    callback(null, false);
                }, handler.conf.get("INVALID_PASS_MS_DELAY"));
            }
            else if(!extendValidity)
                callback(null, uid, token);
            else
                extendTokenValidity(uid);
        });
    
        function extendTokenValidity(uid) {
            var validity = Date.now() + handler.conf.get("TOKEN_VALIDITY_MS");
            handler.db.storeUserTokenValidityInDb(token, validity, function(err) {
                if(err) {
                    console.log("Could not extend token from", table);
                    callback(err);
                }
                else
                    callback(null, uid, token);
            });
        }
    },

    userStatus: function(handler, uid, callback) {
        handler.db.getAdminStatusFromDb(uid, function(err, isAdmin) {
            if(err) {
                console.log("Could not check admin status", err);
                callback(err);
            }
            else {
                if(isAdmin == 1) {
                    console.log("User is admin");
                    handler.isAdmin = true;
                }
                callback();
            }
        });
    }
}