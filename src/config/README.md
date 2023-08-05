# Configuration files

The Konqueror provides the option for operators to customise the network footprint of the communications between Listener and Implant.
Two templates are provided, one for each component.

## Listener template

You can use the Listener's template file to customise the Listener. This below is how it looks:

```json
{
  "Endpoint": {
    "Address": "127.0.0.1:9002",      
    "Name": "/result:/domain:/back",  
    "UUID": "ce7070f3-1b28-4229-a33d-beb19a576048"
  },
  "GETResponse": {
    "Content-Type": "application/json",
    "Encoding-Type": "utf-8",
    "Set-Cookie": "PHPSESSID=test"
  },
  "POSTResponse": {
    "Content-Type": "application/json",
    "Content-Length": "9001",
    "Set-Cookie": "PHPSESSID=test"
  },
  "Options": {
    "SleepTime": 10,
    "APIAddress": "127.0.0.1:9001",
    "404": "not_found.html",  
    "gRPCServerAddress": "127.0.0.1:9003"
  }
}
```

The **Endpoint** field can be used to set:
* Address to bind to for the Listener - Format should be **ip/domain:port**
* What endpoints should the Listener listen for connection from the Implant - Should be separated by a **:**
* The UUID of the Listener

The **GETResponse** and **POSTResponse** fields can be used to set any header that the Listener should return for GET and POST requests respectively. The format should be **Header:Value**.

The **Options** field can be used to set:
* How long between each request to the API Server
* The address of the API - The format should be **ip/domain:port**
* A custom page to return when an invalid endpoint is hit. This should be an HTML file.
* The address of the gRPC API exposed by the team server. The format should be **ip/domain:port**. 

## Implant template

You can use the Implant's template file to customise the Implant. This below is how it looks:

```json
{
  "GETRequest": {
    "User-Agent": "The Konqueror v0.1.0",
    "Accept": "*/*",
    "Host": "thekonqueror.com",
    "Cookie": "PHPSESSID=token",
    "X-Requested-With": "XMLHttpRequest"
  },
  "POSTRequest": {
    "User-Agent": "The Konqueror v0.1.0",
    "Content-Type": "application/json",
    "Host": "localhost"
  },
  "Endpoint": {
    "Address": "127.0.0.1:9002",  
    "Name": "/result:/domain:/back",      
    "UUID": "ce7070f3-1b28-4229-a33d-beb19a576048"
  },
  "Options": {
    "SleepTime": "10",
    "Jitter": "5",
    "KillDate": "2022-12-12 15:04:22",
    "MaxRetry": "5",
    "AESKey": "thekonqueror",
    "HMACKey": "thekonqueror"
  }
}
```

The **GETRequest** and **POSTRequest** fields can be used to set any header that the Implant should send for GET and POST requests respectively. The format should be **Header:Value**.

The **Endpoint** field can be used to set:
* Address of the Listener - Format should be **ip/domain:port**
* What endpoints is the Listener listening - Should be separated by a **:**
* The UUID of the Listener

The **Options** field can be used to set:
* How long to sleep between each request to the Listener
* Jitter to add randomness to the sleep pattern
* When to kill the Implant automatically
* How many failed attempts to contact the Listener before killing itself
* The AESKey used for encrypting a **Task**
* The HMACKey to create a message signature of the **Task**
