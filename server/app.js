// Include
var express = require('express');
var app = express();
var server = require('http').createServer(app);
var fs = require('fs')
var crypto = require('crypto')
var prime 

// Variables
var port = 8080

app.configure(function () {
    app.set('port', process.env.PORT || port);
    app.use(express.cookieParser());
    app.use(express.bodyParser());
    app.use(express.bodyParser({
        uploadDir: __dirname + '/temp'
    }));

});



app.post('/auth', function (req, res) {
    console.log("Auth Received. Performing Auth-DH")
    var alicePub = req.body.publicKey
    
    var bob = crypto.createDiffieHellman(prime, 'hex');
    bob.generateKeys('hex');
    var bobPub = bob.getPublicKey('hex');
    
    
    res.send(JSON.stringify({"publicKey":bobPub, "signature":"SSSDDDDD"}))

    var bobAliceSecret = bob.computeSecret(alicePub, 'hex', 'hex');
    console.log("SHARED SECRET: " + bobAliceSecret)
    
});


// only starts the server if the shared prime key was read successfully
fs.readFile('keys/primesecret.key', 'utf8', function (err, data) {
    if (err) {
        return console.log(err);
    }
    prime = data
    server.listen(app.get('port'), function () {
        console.log('Server started at Port: ' + app.get('port'));
    });

});