// node.js 0.5 Diffie-Hellman example          
var crypto = require("crypto");
var fs = require('fs')
var http = require('http')
var ursa = require('ursa')
var moment = require('moment')

// Configuration variables
var serverURL = 'localhost'

// Variables definitions
var alice
var StringDecoder = require('string_decoder').StringDecoder;
var decoder = new StringDecoder('utf8');
var rbytes = require('rbytes');

var nounce = rbytes.randomBytes(16);


// Variables definitions

var DH_PRIVATE_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/DHPrivateKey.key"));
var RSA_PRIVATE_KEY = fs.readFileSync(__dirname + "/keys/privateKey.pem");
var RSA_PUBLIC_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/publicKey.pem"));
var SERVER_PUBLIC_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/serverPubKey.pub"));
var SHARED_PRIME = decoder.write(fs.readFileSync(__dirname + "/keys/primesecret.key"));
var _id = ''
var UUID = '0c636d769725c21f030d6d41620f8fce15469aaaa4b622d66512343f3a25176d'

fs.readFile('keys/secrets.json', 'utf8', function (err, data) {
    if (err) {
        console.log("ERROR!")
        return console.log(err);
    }
    console.log("INSIDE FILE")
    data = JSON.parse(data)
    _id = data._id
    UUID = data.UUID
});

AuthDH(SHARED_PRIME, 'localhost')

// ALICE                                               

function AuthDH(sharedPrime) {
    alice = crypto.createDiffieHellman(SHARED_PRIME, 'hex');
    alice.setPrivateKey(DH_PRIVATE_KEY, 'hex')

    alice.generateKeys('hex');
    var aliceDHPublicKey = alice.getPublicKey('hex');

    var signature = createSignature();

    HTTP_POST({
        "_id": _id,
        "DHPK": aliceDHPublicKey,
        "Signature": signature
    }, function (res) {

        // TODO VALIDATE SERVER!!

        var bobDHpublicKey = res.DHPK

        console.log(res)
        var SHAREDSecret = alice.computeSecret(bobDHpublicKey, 'hex', 'hex');
        console.log("SHARED SECRET: " + SHAREDSecret)

    })
}

function createSignature() {
    var RSA = ''
    RSA = ursa.createPublicKey(SERVER_PUBLIC_KEY);

    var TS = moment().format("YYYY-MM-DD HH:mm:ss")

    console.log("Nounce: " + nounce)
    console.log("TS: " + TS)

    // ciphering with server public key
    var encoded = RSA.encrypt(nounce + TS, 'utf8', 'hex')
    console.log("Encoded with public key: " + encoded)
    console.log("Encoded with public key (Length): " + encoded.length)

    return encoded

}


function HTTP_POST(postData, callback) {
    postData = JSON.stringify(postData)

    var headers = {
        'Content-Type': 'application/json',
        'Content-Length': postData.length
    };

    var options = {
        host: serverURL,
        port: 8080,
        path: '/auth',
        method: 'POST',
        headers: headers
    };

    // Setup the request.  The options parameter is
    // the object we defined above.
    var req = http.request(options, function (res) {
        res.setEncoding('utf-8');

        var responseString = '';

        res.on('data', function (data) {
            responseString += data;
        });

        res.on('end', function () {
            console.log(responseString)
            callback(JSON.parse(responseString));


        });
    });

    req.on('error', function (e) {
        // TODO: handle error.
        console.log("ERR: " + e)
    });
    req.write(postData);
    req.end();

}