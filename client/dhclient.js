// node.js 0.5 Diffie-Hellman example          
var crypto = require("crypto");
var fs = require('fs')
var http = require('http')
var ursa = require('ursa')

// Configuration variables
var serverURL = 'localhost'

// Variables definitions
var alice
var PRIVATE_KEY = fs.readFileSync(__dirname + "/keys/privateKey.pem");
var SHARED_PRIME = fs.readFileSync(__dirname + "/keys/primesecret.key");

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
    console.log("SharedPrime: " + sharedPrime)
    alice = crypto.createDiffieHellman('a2328aa5fb2af7b16b80142fc0771bebd7f8aceb106d2adab4219be36729a5b005d3d1268417416c4834f22862cb7a21ea2397f1de743015bf1294a8163d57d3', 'hex');
    alice.generateKeys('hex');
    var aliceDHPublicKey = alice.getPublicKey('hex');
    
    // cipher UUID with private key
   
     HTTP_POST({"_id":_id,"DHPK":aliceDHPublicKey, "Signature":"SSSDDDDD"}, function(res){
         
         // TODO VALIDATE SERVER!!
         
         var bobDHpublicKey = res.DHPK
         var SHAREDSecret = alice.computeSecret(bobDHpublicKey,'hex','hex');
         console.log("SHARED SECRET: " + SHAREDSecret)
     
     })
        
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

