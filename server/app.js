// Include
var express = require('express');
var app = express();
var server = require('http').createServer(app);
var fs = require('fs')
var crypto = require('crypto')

var BigInt = require('./libraries/BigInt');

// Configuration variables
var serverURL = 'localhost'

var StringDecoder = require('string_decoder').StringDecoder;
var decoder = new StringDecoder('utf8');


// Variables definitions
var PRIVATE_KEY =  fs.readFileSync(__dirname + "/keys/privateKey.pem");
var PUBLIC_KEY =  fs.readFileSync(__dirname + "/keys/publicKey.pem");
var SHARED_PRIME = decoder.write(fs.readFileSync(__dirname + "/keys/primesecret.key"));

// Extracting Private Key from .pem
//PRIVATE_KEY = PRIVATE_KEY.replace("-----BEGIN RSA PRIVATE KEY-----","")
//PRIVATE_KEY = PRIVATE_KEY.replace("-----END RSA PRIVATE KEY-----","")
//PRIVATE_KEY = PRIVATE_KEY.replace(/(\r\n|\n|\r)/gm, '')
//console.log(PRIVATE_KEY)


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
    var bob = crypto.createDiffieHellman(SHARED_PRIME, 'hex');
    console.log("PRIVATE 1: " + PRIVATE_KEY)
 //   bob.setPrivateKey(PRIVATE_KEY)
 
    bob.generateKeys('hex');
    var bobDHPublicKey = bob.getPublicKey('hex');
    console.log("PRIVATE: " + bob.getPrivateKey('hex'))

    console.log("Size Default: " + Buffer.byteLength(bob.getPrivateKey('hex'), 'utf8') )
    console.log("Size RSA: " + Buffer.byteLength(PRIVATE_KEY, 'utf8'))
    // Doing my own.
//    var bobDHPublicKey = DH_GEN_DHPK(SHARED_PRIME, PRIVATE_KEY)
//    console.log(bobDHPublicKey)
//    var SESSION_KEY = DH_GEN_SK(SHARED_PRIME, PRIVATE_KEY, aliceDHPublicKey)
//    console.log("SHARED SECRET: " + SESSION_KEY)
    
    
    res.send(JSON.stringify({
        "_id":_id,
        "DHPK": bobDHPublicKey,
        "Signature": "SSSDDDDD"
    }))

//    var SHAREDSecret = bob.computeSecret(aliceDHPublicKey, 'hex', 'hex');
//    console.log("SHARED SECRET: " + SHAREDSecret)

});



// Generates Public DH Key 
function DH_GEN_DHPK(SHARED_PRIME, PRIVATE_KEY)
{
  var p = SHARED_PRIME 
  var g = BigInt.str2bigInt("2", 10, 80);       
  var a = PRIVATE_KEY

  return DHPK = BigInt.powMod(g,a,p);
}

// Calculate Session Key based on DHPK
function DH_GEN_SK(SHARED_PRIME,PRIVATE_KEY,DHPK){
    var p = SHARED_PRIME;
    var a = PRIVATE_KEY
    var SK = BigInt.powMod(B, a, p);
    return SK

}

server.listen(app.get('port'), function () {
    console.log('Server started at Port: ' + app.get('port'));
});