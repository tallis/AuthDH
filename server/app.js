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

var DH_PRIVATE_KEY =  decoder.write(fs.readFileSync(__dirname + "/keys/DHPrivateKey.key"));
var RSA_PRIVATE_KEY =  decoder.write(fs.readFileSync(__dirname + "/keys/privateKey.pem"));
var RSA_PUBLIC_KEY =  decoder.write(fs.readFileSync(__dirname + "/keys/publicKey.pem"));
var SHARED_PRIME = decoder.write(fs.readFileSync(__dirname + "/keys/primesecret.key"));

// Extracting Private Key from .pem
RSA_PRIVATE_KEY = RSA_PRIVATE_KEY.replace("-----BEGIN RSA PRIVATE KEY-----","")
RSA_PRIVATE_KEY = RSA_PRIVATE_KEY.replace("-----END RSA PRIVATE KEY-----","")
RSA_PRIVATE_KEY = RSA_PRIVATE_KEY.replace(/(\r\n|\n|\r)/gm, '')
console.log("RSA Private Key: " + RSA_PRIVATE_KEY)


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
   
    //var bob = crypto.createDiffieHellman(SHARED_PRIME, 'hex');
  


    // Doing my own.
    var bobDHPublicKey = DH_GEN_DHPK(SHARED_PRIME, DH_PRIVATE_KEY)
    console.log("Received Public key: " + bobDHPublicKey)
    var SESSION_KEY = DH_GEN_SK(SHARED_PRIME, DH_PRIVATE_KEY, aliceDHPublicKey)
    console.log("SHARED SECRET: " + SESSION_KEY)
    
    
    res.send(JSON.stringify({
        "_id":_id,
        "DHPK": bobDHPublicKey,
        "Signature": "SSSDDDDD"
    }))

//    var SHAREDSecret = bob.computeSecret(aliceDHPublicKey, 'hex', 'hex');
//    console.log("SHARED SECRET: " + SHAREDSecret)

});



// Generates Public DH Key 
function DH_GEN_DHPK(SHARED_PRIME, DH_PRIVATE_KEY)
{
    console.log("DH PRIVATE KEY LEN: " + DH_PRIVATE_KEY.length)
  var p = SHARED_PRIME 
  var g = BigInt.str2bigInt("2", 10, 80);       
  var a = DH_PRIVATE_KEY

  return DHPK = BigInt.powMod(g,a,p);
}

// Calculate Session Key based on DHPK
function DH_GEN_SK(SHARED_PRIME,DH_PRIVATE_KEY,DHPK){
    var p = SHARED_PRIME;
    var a = DH_PRIVATE_KEY
    var SK = BigInt.powMod(B, a, p);
    return SK

}

server.listen(app.get('port'), function () {
    console.log('Server started at Port: ' + app.get('port'));
});