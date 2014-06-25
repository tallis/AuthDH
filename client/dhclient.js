// node.js 0.5 Diffie-Hellman example          
var crypto = require("crypto");
var fs = require('fs')
var http = require('http')

var serverURL = 'localhost'

var alice

//>>>> Generating a prime!!! put this into a separated file                                              
//var server = crypto.createDiffieHellman(512,'hex');
//var prime = server.getPrime('hex');


fs.readFile('keys/primesecret.key', 'utf8', function (err, data) {
    if (err) {
        return console.log(err);
    }
    var prime = data
    AuthDH(prime, 'localhost')


});

// ALICE                                               
function AuthDH(sharedPrime) {
    alice = crypto.createDiffieHellman(sharedPrime, 'hex');
    alice.generateKeys('hex');
    var alicePub = alice.getPublicKey('hex');
   
     HTTP_POST({"publicKey":alicePub, "signature":"SSSDDDDD"}, function(res){
         // response received. calculating Session key and validating sender
         var aliceBobSecret = alice.computeSecret(res.publicKey,'hex','hex');
         console.log("SHARED SECRET: " + aliceBobSecret)
     
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


//var bob = crypto.createDiffieHellman(prime,'hex');
//bob.generateKeys('hex');
//var bobPub = bob.getPublicKey();
// 
//var bobAliceSecret = bob.computeSecret(alicePub,null, 'hex');