const sqlite3 = require('sqlite3');

function Db(DB_NAME, BUSY_TIMEOUT) {
    // We have to use a new db object for every transaction to assure isolation
    // See https://github.com/mapbox/node-sqlite3/issues/304
    this.db = new sqlite3.Database(DB_NAME);
    this.db.configure("busyTimeout", BUSY_TIMEOUT);
}

Db.prototype.close = function() {
    this.db.close();
}

Db.prototype.getUserHashFromDb = function(username, callback) {

    this.db.get("SELECT uid, hash FROM users WHERE username = ?", username, function(err, row) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else if(!row)
            callback();
        else
            callback(null, row.uid, row.hash);
    });
}

Db.prototype.getTokenValidityFromDb = function(table, token, callback) {

    this.db.get("SELECT uid,validity FROM "+table+" WHERE token = ?", token, function(err, row) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else if(!row)
            callback();
        else 
            callback(null, row.validity, row.uid);
    });
}

Db.prototype.getUserDataUsingUidFromDb = function(uid, callback) {

    this.db.get("SELECT userdata FROM usersdata WHERE uid = ?", uid, function(err, row) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else if(!row)
            callback();
        else
            callback(null, row.userdata);
    });
}

Db.prototype.getUserDataUsingUsernameFromDb = function(username, callback) {

    this.db.get("SELECT userdata FROM usersdata WHERE uid = (SELECT uid FROM users WHERE username = ?)", username, function(err, row) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else if(!row)
            callback();
        else
            callback(null, row.userdata);
    });
}

Db.prototype.getTrustedUrlsFromDb = function(domain, callback) {

    this.db.get("SELECT reseturi FROM trustedurls WHERE domain = ?", domain, function(err, row) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else if(!row)
            callback();
        else
            callback(null, row.reseturi);
    });
}

Db.prototype.getUserUidUsingUsernameFromDb = function(username, callback) {

    this.db.get("SELECT uid FROM users WHERE username = ?", username, function(err, row) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else if(!row)
            callback();
        else
            callback(null, row.uid);
    });
}

Db.prototype.getAdminStatusFromDb = function(uid, callback) {

    this.db.get("SELECT admin FROM users WHERE uid = ?", uid, function(err, row) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else if(!row)
            callback();
        else
            callback(null, row.admin);
    });
}

Db.prototype.getAllUsersFromDb = function(callback) {

    var result = [];
    this.db.each("SELECT username FROM users LIMIT 300", [], function(err,row) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else result.push(row.username);
    }, function(err,nrows) {
        if(err) {
            console.log(err);
            callback(err);
        }
        else
            callback(null,result);
    });
}

Db.prototype.storeTokenInDb = function(table, uid, token, validity, callback) {

    this.db.run("UPDATE "+table+" SET token = ?, validity = ? WHERE uid = ?", token, validity, uid, function(err) {
        if(!err && this.changes !== 1) err = this.sql+" validity: "+validity+" uid: "+uid+" was run successfully but made no changes";
        if(err) console.log(err);
        callback(err);
    });
}

Db.prototype.storeUserHashInDb = function(uid, hash, callback) {

    this.db.run("UPDATE users SET hash = ? WHERE uid = ?", hash, uid, function(err) {
        if(!err && this.changes !== 1) err = this.sql+" uid: "+uid+" was run successfully but made no changes";
        if(err) console.log(err);
        callback(err);
    });
}

Db.prototype.storeUserTokenValidityInDb = function(token, validity, callback) {

    this.db.run("UPDATE tokens SET validity = ? WHERE token = ?", validity, token, function(err) {
        if(!err && this.changes !== 1) err = this.sql+" validity: "+validity+" was run successfully but made no changes";
        if(err) console.log(err);
        callback(err);
    });
}

Db.prototype.storeUserDataInDb = function(uid, userdata, callback) {

    this.db.run("UPDATE usersdata SET userdata = ? WHERE uid = ?", userdata, uid, function(err) {
        if(!err && this.changes !== 1) err = this.sql+" uid: "+uid+" userdata: "+userdata+" was run successfully but made no changes";
        if(err) console.log(err);
        callback(err);
    });
}

module.exports = Db;
