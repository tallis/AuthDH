// Include
var express = require('express');
var app = express();
var server = require('http').createServer(app);
var fs = require('fs')
var crypto = require('crypto')
var ursa = require('ursa')
var StringDecoder = require('string_decoder').StringDecoder;
var decoder = new StringDecoder('utf8');
var rbytes = require('rbytes');
var moment = require('moment')


// Variables definitions
var DH_PRIVATE_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/DHPrivateKey.key"));
var RSA_PRIVATE_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/serverPrivate.pem"));
var SHARED_PRIME = decoder.write(fs.readFileSync(__dirname + "/keys/primesecret.key"));

// Setting DIFFIE HELLMAN
console.log("Setting up DiffieHellman")
var DIFFIE_HELLMAN = crypto.createDiffieHellman(SHARED_PRIME, 'hex');
DIFFIE_HELLMAN.setPrivateKey(DH_PRIVATE_KEY, 'hex')
DIFFIE_HELLMAN.generateKeys('hex');


// Variables
var port = 8080
var _id = "server"

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
    var clientID = req.body._id
    var clientDHPK = req.body.DHPK
    var clientSignature = req.body.Signature

    var nounce = validateSignature(clientSignature)
    var encodedSignature = createSignature(nounce, clientID)

    res.send(JSON.stringify({
        "_id": _id,
        "DHPK": DIFFIE_HELLMAN.getPublicKey('hex'),
        "Signature": encodedSignature
    }))

    var SHARED_SECRET = DIFFIE_HELLMAN.computeSecret(clientDHPK, 'hex', 'hex');
    console.log("DH SHARED SECRET: " + SHARED_SECRET)
    // store session key.

});



function validateSignature(signature) {

    RSA = ursa.createPrivateKey(RSA_PRIVATE_KEY);
    var decoded = RSA.decrypt(signature, 'hex')
    decoded = decoder.write(decoded).split("/")

    var nounce = decoded[0]
    var TS = decoded[1]
    var ID = decoded[2]

    console.log("DECODED RSA Nounce: " + nounce)
    console.log("DECODED RSA Timestamp: " + TS)
    console.log("DECODED RSA ID: " + ID)

    return nounce
}


function createSignature(nounce, ID) {
    var TS = moment().format("YYYY-MM-DD HH:mm:ss")
    var NODE_PUBLIC_KEY = decoder.write(fs.readFileSync(__dirname + "/certificates/" + ID + ".pub"));
    RSA = ursa.createPublicKey(NODE_PUBLIC_KEY);

    // ciphering with server public key
    var encoded = RSA.encrypt(nounce, 'utf8', 'hex')
    return encoded

}



server.listen(app.get('port'), function () {
    console.log('Server started at Port: ' + app.get('port'));
});