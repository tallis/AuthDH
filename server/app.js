// Include
var express = require('express');
var app = express();
var server = require('http').createServer(app);
var fs = require('fs')
var crypto = require('crypto')
var ursa = require('ursa')

// Configuration variables
var serverURL = 'localhost'

var StringDecoder = require('string_decoder').StringDecoder;
var decoder = new StringDecoder('utf8');
var rbytes = require('rbytes');

var moment = require('moment')

// Variables definitions

var DH_PRIVATE_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/DHPrivateKey.key"));
var RSA_PRIVATE_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/privateKey.pem"));
var RSA_PUBLIC_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/publicKey.pem"));
var SHARED_PRIME = decoder.write(fs.readFileSync(__dirname + "/keys/primesecret.key"));

// GLOBAL
console.log("Setting up DiffieHellman")
var DIFFIE_HELLMAN = crypto.createDiffieHellman(SHARED_PRIME, 'hex');
DIFFIE_HELLMAN.setPrivateKey(DH_PRIVATE_KEY, 'hex')
DIFFIE_HELLMAN.generateKeys('hex');

fs.readFile('keys/secrets.json', 'utf8', function (err, data) {
    if (err) {
        return console.log(err);
    }
    data = JSON.parse(data)
    _id = data._id
    UUID = data.UUID
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
    var serverID = req.body._id
    var clientDHPK = req.body.DHPK
    var clientSignature = req.body.Signature
    
    var carlosSignature = "5ab086200239a621132714336c7990e041073d32b6d8690648b2066e18c55730b39fad1e20ad6369d0b9900e8849f4ccbd718b80d7760f0685fdebf5ac8c1edf3b2df8830a248a94dede6b4763f6a1ba458f0139564eb8da7e3579893d84f415dcf7a33d824b96805513fc7e0561081295c3dc6b3562b864e05d8da60826cbfb"

    // TODO Calculate Signature
        
    var nounce = validateSignature(carlosSignature)
    
    var encodedSignature = createSignature(nounce,156)
    
    
    res.send(JSON.stringify({
        "_id": _id,
        "DHPK": DIFFIE_HELLMAN.getPublicKey('hex'),
        "Signature":encodedSignature
    }))

    var SHARED_KEY = DIFFIE_HELLMAN.computeSecret(clientDHPK, 'hex', 'hex');
    console.log("SHARED KEY: " + SHARED_KEY)
    // store session key.

});



function validateSignature(signature) {
    var RSA = ''
    PRIVATE_RSA = ursa.createPrivateKey(RSA_PRIVATE_KEY);
    
    var decoded = PRIVATE_RSA.decrypt(signature, 'hex')
    decoded = decoder.write(decoded)
    decoded = decoded.split("/")

    var nounce = decoded[0]
    var TS =  decoded[1]
    var nodeID = decoded[2]
   
    console.log("DECODED RSA Nounce: " + nounce)
    console.log("DECODED RSA Timestamp: " + TS)
    console.log("DECODED RSA nodeID: " + nodeID)
    
    return nounce
}


function createSignature(nounce,nodeID) {
    var TS = moment().format("YYYY-MM-DD HH:mm:ss")
    
    var NODE_PUBLIC_KEY = decoder.write(fs.readFileSync(__dirname + "/certificates/"+nodeID+".pub"));
    
    var RSA = ''
    RSA = ursa.createPublicKey(NODE_PUBLIC_KEY);

    console.log("Nounce: " + nounce)

    // ciphering with server public key
    var encoded = RSA.encrypt(nounce, 'utf8', 'hex')
    console.log("Encoded with public key: " + encoded)
    console.log("Encoded with public key (Length): " + encoded.length)

    return encoded

}



server.listen(app.get('port'), function () {
    console.log('Server started at Port: ' + app.get('port'));
});