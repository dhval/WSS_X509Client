# WSS_X509Client
A dotnet core WS-Security client for signing SOAP message with X.509 Certificate.


#### Create appsettings.json which provide input parameters to console app.

```
{
  "version": "1.0",
  "endpoint": "https://ws.gateway.org/Information",
  "SOAPAction": "",
  "client-certificate": "client.pfx",
  "server-certificate": "server.cer",
  "certificate-password": "certpwd",
  "source-xml": "sample.xml"
}
```

- endpoint : The webservice url
- client certificate/key : Used to sign the SOAP Body
- certificate password : The password for the client key
- server certificate : Validate server certificate before establishing TLS session.
- source xml : The XML request that needs to be wrapped in SOAP Body.
