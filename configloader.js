
const fs = require("fs");

var confKeys = {
    "DB_NAME":                  "indri-auth.db",
    "SERVER_PORT":              8000,
    "BUSY_TIMEOUT":             2000,
    "INVALID_PASS_MS_DELAY":    3000,
    "TOKEN_BYTE_LENGTH":        33, //264 bits, no base64 = padding
    "TOKEN_VALIDITY_MS":        60 *60 * 1000, // 1 hour
    "GET_DEFAULT_RESPONSE":     {
                                    "message": "Welcome on the indri-auth service",
                                    "doc": "https://github.com/indriApollo/indri-auth"
                                },
    "USERPASS_MIN_BYTELENGTH":  12,
    "BCRYPT_SALT_SIZE":         16,
    "NODEMAILER_FROM":          "no-reply@indriapollo.be",
    "NODEMAILER_SUBJECT":       "Password reset | %domain%",
    "NODEMAILER_TEXT":          "You made a request for a new password on '%domain%'\r\n"
                                +"Visit this link to set a new password : %url%\r\n",
    "SMTP_SERVER":              "",
    "SMTP_PORT":                587,
    "SMTP_USER":                "",
    "SMTP_PASSWORD":            ""
}

function log(...args) {
    console.log("[config]", ...args);
}

module.exports = {

    // load config.json
    load: function() {
        try {
            var confFile = fs.readFileSync("config.json","utf8");
            var config = JSON.parse(confFile);
        }
        catch(err) {
            console.log("Could not read configuration from config.json");
            console.log(err);
            return false;
        }

        for(var k in config) {
            if(confKeys.hasOwnProperty(k)) {
                confKeys[k] = config[k];
            }
            else
                log("Unknown key", k);
        }

        for(var k in confKeys) {
            if(k.match(/password/i))
                log(k,"-> ********");
            else
                log(k, "->", confKeys[k]);
        }
    },

    get: function(confKey) {
        return confKeys[confKey];
    }
}