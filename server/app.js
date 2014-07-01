// Include
var express = require('express');
var app = express();
var server = require('http').createServer(app);
var fs = require('fs')
var crypto = require('crypto')


// Configuration variables
var serverURL = 'localhost'

// Variables definitions
var PRIVATE_KEY = fs.readFileSync(__dirname + "/keys/privateKey.pem");
var SHARED_PRIME = fs.readFileSync(__dirname + "/keys/primesecret.key");



fs.readFile('keys/secrets.json', 'utf8', function (err, data) {
    if (err) { return console.log(err);}
    data = JSON.parse(data)
    _id = data._id
    UUID = data.UUID
});



fs.readFile('keys/secrets.json', 'utf8', function (err, data) {
    if (err) { return console.log(err);}
    data = JSON.parse(data)
    var _id = data._id
    var UUID = data.UUID
});

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
    var aliceID = req.body._id
    var aliceDHPublicKey = req.body.DHPK
    console.log(SHARED_PRIME)
    SHARED_PRIME = "a2328aa5fb2af7b16b80142fc0771bebd7f8aceb106d2adab4219be36729a5b005d3d1268417416c4834f22862cb7a21ea2397f1de743015bf1294a8163d57d3"
        console.log(SHARED_PRIME)
    var bob = crypto.createDiffieHellman(SHARED_PRIME, 'hex');
    bob.generateKeys('hex');
    var bobDHPublicKey = bob.getPublicKey('hex');


    res.send(JSON.stringify({
        "_id":_id,
        "DHPK": bobDHPublicKey,
        "Signature": "SSSDDDDD"
    }))

    var SHAREDSecret = bob.computeSecret(aliceDHPublicKey, 'hex', 'hex');
    console.log("SHARED SECRET: " + SHAREDSecret)

});


server.listen(app.get('port'), function () {
    console.log('Server started at Port: ' + app.get('port'));
});