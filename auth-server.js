#!/usr/bin/env node

const http = require("http"); // no https because we are behind a proxy
const nodemailer = require("nodemailer");
const urlHelper = require("url");
const conf = require("./configloader.js");
const cm = require("./common.js");

const httpGetHandler = require("./httpGetHandler.js")
const httpPostHandler = require("./httpPostHandler.js")

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
    var url = urlHelper.parse(decodeURIComponent(request.url));
    var pathname = url.pathname;

    var body = [];
    
    response.on("error", function(err) {
        console.error(err);
    });
    
    request.on("error", function(err) {
        console.error(err);
        response.statusCode = 500;
        response.end();
    
    }).on("data", function(chunk) {
        body.push(chunk);
    }).on("end", function() {
        body = Buffer.concat(body).toString();
    
        switch(method) {
            case "GET":
                httpGetHandler(conf, pathname, headers, response);
                break;
    
            case "POST":
                httpPostHandler(conf, pathname, headers, body, smtp, response);
                break;
    
            case "OPTIONS":
                handleCORS(response);
                break;
    
            default:
                cm.respond(response, "Unsupported http method", 400);
                break;
        }
    });
}).listen(conf.get("SERVER_PORT"));
console.log("server listening on port", conf.get("SERVER_PORT"));

function handleCORS(response) {
    
    /*
     * Handle Cross-Origin Resource Sharing (CORS)
     *
     * See : https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS#Preflighted_requests
     */
        
    // The preflighted requests expects http 200 for a successful request
    response.statusCode = 200;
    // We allow requests from any origin
    response.setHeader("Access-Control-Allow-Origin", "*");
    // We have to explicitly allow Auth-Token since it"s a custom header
    response.setHeader("Access-Control-Allow-Headers", "Auth-Token,User-Agent,Content-Type"); //can"t use * !
    // We allow POST, GET and OPTIONS http methods
    response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    response.end();
}
