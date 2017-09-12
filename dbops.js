
module.exports = {

    getUserHashFromDb: function(db, username, callback) {
        db.get("SELECT uid, hash FROM users WHERE username = ?", username, function(err, row) {
            if(err) {
                console.log(err);
                callback([err]);
            }
            else if(!row)
                callback([]);
            else
                callback([null, row.uid, row.hash]);
        })
    },

    getTokenValidityFromDb: function(db, table, token, callback) {
        db.get("SELECT uid,validity FROM "+table+" WHERE token = ?", token, function(err, row) {
            if(err) {
                console.log(err);
                callback([err]);
            }
            else if(!row)
                callback([]);
            else 
                callback([null, row.validity, row.uid]);
        });
    },

    getUserDataFromDb: function(db, uid, callback) {
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
    },

    getTrustedUrlsFromDb: function(db, domain, callback) {
        db.get("SELECT reseturi FROM trustedurls WHERE domain = ?", domain, function(err, row) {
            if(err) {
                console.log(err);
                callback([err]);
            }
            else if(!row)
                callback([]);
            else
                callback([null, row.reseturi]);
        });
    },

    getUserUidUsingUsernameFromDb: function(db, username, callback) {
        db.get("SELECT uid FROM users WHERE username = ?", username, function(err, row) {
            if(err) {
                console.log(err);
                callback([err]);
            }
            else if(!row)
                callback([]);
            else
                callback([null, row.uid]);
        });
    },

    storeTokenInDb: function(db, table, uid, token, validity, callback) {
        db.run("UPDATE "+table+" SET token = ?, validity = ? WHERE uid = ?", token, validity, uid, function(err) {
            if(!err && this.changes !== 1) err = this.sql+" was run successfully but made no changes";
            if(err) console.log(err);
            callback([err]);
        })
    },

    storeUserHashInDb: function(db, uid, hash, callback) {
        db.run("UPDATE users SET hash = ? WHERE uid = ?", hash, uid, function(err) {
            if(!err && this.changes !== 1) err = this.sql+" was run successfully but made no changes";
            if(err) console.log(err);
            callback([err]);
        })
    },

    storeUserTokenValidityInDb: function(db, token, validity, callback) {
        db.run("UPDATE tokens SET validity = ? WHERE token = ?", validity, token, function(err) {
            if(!err && this.changes !== 1) err = this.sql+" was run successfully but made no changes";
            if(err) console.log(err);
            callback([err]);
        })
    }
}
