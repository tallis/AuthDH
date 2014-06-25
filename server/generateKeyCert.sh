#!/bin/bash

echo 'Generating private key'
openssl genrsa -out privateKey.pem 1024
echo 'Generating Certificate Signing Request (CSR). Please fill the fields.'
openssl req -new -key privateKey.pem -out serverCSR.pem
echo 'Generating X.509 public-key certificate.'
openssl x509 -req -in serverCSR.pem -signkey privateKey.pem -out PKCertificate.pem
echo 'Moving certificates'
mv *.pem keys/
echo 'Done.'