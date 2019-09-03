# WSS_X509Client
A dotnet core WS-Security client for signing SOAP message with X.509 Certificate.


#### Create appsettings.json which provide input parameters to console app.

```
{
  "version": "1.0",
  "endpoint": "https://ws.x509.gateway.org/Information",
  "SOAPAction": "",
  "base-path": "/path/to/other/files/",
  "client-certificate": "client.pfx",
  "server-certificate": "server.cer",
  "certificate-password": "certpwd",
  "source-xml": "sample.xml"
}
```

- endpoint : The webservice url
- client certificate/key : Used to sign the SOAP Body
- base path : Directory where all files reside, ending with '/'
- certificate password : The password for the client key
- server certificate : Validate server certificate before establishing TLS session.
- source xml : The XML request that will be wrapped in SOAP Body.


#### Executing Client

Must be absolute path to the settings file for cross platform compatibility.

```
 dotnet run --project WSSClient.csproj /Users/dhval/WSSClient/appsettings.json 

 dotnet run --project WSSClient.csproj "c:/Users/dhval/WSSClient/appsettings.json" 
```

[Specify Arguments in VS](https://github.com/dhval/WSS_X509Client/blob/master/docs/application_arguments.png)

#### [WS-Security X.509 Certificate Token Profile](http://docs.oasis-open.org/wss-m/wss/v1.1.1/wss-x509TokenProfile-v1.1.1.html)

- WS-Security X.509 Certificate Token Profile is an OASIS specification that
 describes the profile (specific mechanisms and procedures) on how the
 "BinarySecurityToken" element defined in WS-Security standard can be used to
 include X.509 certificate as a means of identifying the sender of a SOAP message
 to the receiver.

- An X.509 Certificate is a binding of a public key and its owner certified by
 a Certificate Authority (CA). It can be used to authenticate the certificate
 owner if the CA can be trusted..

Here is a SOAP request message example that contains a wsse:BinarySecurityToken
 element containing an X.509 certificate.
 



#### Disclaimer
 The material embodied in this software is provided to you "as-is" and without warranty of any kind, express,
 implied or otherwise, including without limitation, any warranty of fitness for a particular purpose. 
 