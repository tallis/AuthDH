// node.js 0.5 Diffie-Hellman example          
var crypto = require("crypto");
var fs = require('fs')
var http = require('http')
var ursa = require('ursa')
var moment = require('moment')
var assert = require('assert')

// Variables definitions
var alice
var StringDecoder = require('string_decoder').StringDecoder;
var decoder = new StringDecoder('utf8');
var rbytes = require('rbytes');

// Variables definitions
var DH_PRIVATE_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/DHPrivateKey.key"));
var SHARED_PRIME = decoder.write(fs.readFileSync(__dirname + "/keys/primesecret.key"));
var RSA_PRIVATE_KEY = fs.readFileSync(__dirname + "/keys/privateKey.pem");
var SERVER_PUBLIC_KEY = decoder.write(fs.readFileSync(__dirname + "/keys/serverPubKey.pub"));

// Configuration variables
var serverURL = 'localhost'
var _id = 'alice'


AuthDH(SHARED_PRIME, 'localhost')

function AuthDH(sharedPrime) {
    alice = crypto.createDiffieHellman(SHARED_PRIME, 'hex');
    alice.setPrivateKey(DH_PRIVATE_KEY, 'hex')
    alice.generateKeys('hex');

    var aliceDHPublicKey = alice.getPublicKey('hex');

    var nounce = rbytes.randomBytes(16);
    var TS = moment().format("YYYY-MM-DD HH:mm:ss");

    var signature = createSignature(nounce + "/" + TS + "/" + _id);

    HTTP_POST({
        "_id": _id,
        "DHPK": aliceDHPublicKey,
        "Signature": signature
    }, function (res) {


        var SHARED_SECRET = alice.computeSecret(res.DHPK, 'hex', 'hex');

        var receivedNounce = validateSignature(res.Signature)

        console.log("SENT NOUNCE: " + nounce)
        console.log("SHARED SECRET: " + SHARED_SECRET)
        console.log("RECEIVED NOUNCE: " + receivedNounce)

        try {
            assert.equal(nounce, receivedNounce)
            console.log("Node is formally authenticated")
        } catch (error) {
            if (error == "AssertionError") {
                console.log("Not Authenticated")
            }
        }
    })
}

function createSignature(payload) {

    // ciphering with server public key
    var RSA = ursa.createPublicKey(SERVER_PUBLIC_KEY);
    var encoded = RSA.encrypt(payload, 'utf8', 'hex')
    return encoded
}

function validateSignature(signature) {

    RSA = ursa.createPrivateKey(RSA_PRIVATE_KEY);
    var decoded = RSA.decrypt(signature, 'hex')
    decoded = decoder.write(decoded)

    return decoded
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
        console.log("ERR: " + e)
    });
    req.write(postData);
    req.end();

}