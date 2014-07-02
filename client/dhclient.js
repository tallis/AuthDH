// node.js 0.5 Diffie-Hellman example          
var crypto = require("crypto");
var fs = require('fs')
var http = require('http')
var ursa = require('ursa')

// Configuration variables
var serverURL = 'localhost'

// Variables definitions
var alice
var StringDecoder = require('string_decoder').StringDecoder;
var decoder = new StringDecoder('utf8');


// Variables definitions
var PRIVATE_KEY =  decoder.write(fs.readFileSync(__dirname + "/keys/privateKey.pem"));
var PUBLIC_KEY =  decoder.write(fs.readFileSync(__dirname + "/keys/publicKey.pem"));
var SHARED_PRIME = decoder.write(fs.readFileSync(__dirname + "/keys/primesecret.key"));
var _id = ''
var UUID = ''

fs.readFile('keys/secrets.json', 'utf8', function (err, data) {
    if (err) { return console.log(err);}
    data = JSON.parse(data)
    _id = data._id
    UUID = data.UUID
});

AuthDH(SHARED_PRIME, 'localhost')

// ALICE                                               
function AuthDH(sharedPrime) {
    alice = crypto.createDiffieHellman(SHARED_PRIME, 'hex');
    // set privateKey
    alice.generateKeys('hex');
    var aliceDHPublicKey = alice.getPublicKey('hex');
    
   //createSignature();
   
     HTTP_POST({"_id":_id,"DHPK":aliceDHPublicKey, "Signature":"SSSDDDDD"}, function(res){
         
         // TODO VALIDATE SERVER!!
         
         var bobDHpublicKey = res.DHPK
         var SHAREDSecret = alice.computeSecret(bobDHpublicKey,'hex','hex');
         console.log("SHARED SECRET: " + SHAREDSecret)
     
     })
}

function createSignature(){
        var key = ursa.createPublicKey(PUBLIC_KEY);
        var encoded = key.privateEncrypt(UUID, "utf8", "hex");
    
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

