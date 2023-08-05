# Certs

This folder contains all certificates used by the framework. 

Leaving them here for testing purposes but you might want to create your own CA and certs. 

The CA private key password is **TheKonqueror**, use it to create new client and listener certs with the following commands:

## Create new client certificate

`openssl genrsa -out dir/priv.key 2048`   
`openssl req -new -key dir/priv.key -out dir/request.csr`  
`openssl x509 -req -days 365 -sha256 -in dir/request.csr -CA ca/ca.crt -CAkey ca/ca.key -set_serial $serial -out dir/certificate.crt`  

## Create certs from scratch 

### CA 

* `openssl genrsa -aes256 -out ca/ca.key 4096`
* `chmod 400 ca/ca.key`
* `openssl req -new -x509 -sha256 -days 365 -key ca/ca.key -out ca/ca.crt`
* `chmod 444 ca/ca.crt`
* Verify - `openssl x509 -noout -text -in ca/ca.crt`

### Server 

* `openssl genrsa -out server/server.key 2048`
* `chmod 400 server/server.key`
* `openssl req -new -key server/server.key -sha256 -out server/server.csr`
* `openssl x509 -req -days 365 -sha256 -in server/server.csr -CA ca/ca.crt -CAkey ca/ca.key -set_serial 1 -out server/server.crt`
* Verify - `openssl x509 -noout -text -in server/client-ssl.bauland42.com.crt`