using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Extensions.Configuration;

namespace WSClient
{
    public class Program
    {
  
        public static IConfiguration config { get; set; }

        private static string createSOAPRequest(String srcXML, X509Certificate2 certificate)
        {
            string envelope = null;
            string correlationId = string.Format("uuid-{0}-1", Guid.NewGuid().ToString());
            using (MemoryStream stream = new MemoryStream())
            {
                Encoding utf8 = new UTF8Encoding(false);
                using (var writer = new XmlTextWriter(stream, utf8))
                {
                    DateTime dt = DateTime.UtcNow;
                    string now = dt.ToString("o").Substring(0, 23) + "Z";
                    string plus5 = dt.AddMinutes(5).ToString("o").Substring(0, 23) + "Z";

                    // Add SOAP Envelope
                    writer.WriteStartDocument();
                    writer.WriteStartElement("s", "Envelope", "http://schemas.xmlsoap.org/soap/envelope/");
                    writer.WriteAttributeString("xmlns", "a", null, "http://www.w3.org/2005/08/addressing");
                    writer.WriteAttributeString("xmlns", "u", null, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
                    writer.WriteAttributeString("xmlns", "xsd", null, "http://www.w3.org/2001/XMLSchema");
                    writer.WriteAttributeString("xmlns", "xsi", null, "http://www.w3.org/2001/XMLSchema-instance");

                    // Add SOAP Header
                    writer.WriteStartElement("s", "Header", null);
                    // Add WS
                    writer.WriteStartElement("o", "Security", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");

                    // Add timestamp
                    writer.WriteStartElement("u", "Timestamp", null);
                    writer.WriteAttributeString("u", "Id", null, "_0");
                    writer.WriteElementString("u", "Created", null, now);
                    writer.WriteElementString("u", "Expires", null, plus5);
                    writer.WriteEndElement();

                    // Add Token
                    writer.WriteStartElement("o", "BinarySecurityToken", null);
                    writer.WriteAttributeString("u", "Id", null, correlationId);
                    writer.WriteAttributeString("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
                    writer.WriteAttributeString("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
                    byte[] rawData = certificate.GetRawCertData();
                    writer.WriteBase64(rawData, 0, rawData.Length);
                    writer.WriteEndElement(); //End BinarySecurityToken

                    writer.WriteEndElement(); //End Security
                    writer.WriteEndElement(); //End Header

                    // Add SOAP Body
                    writer.WriteStartElement("s", "Body", null);

                    FileStream fs0 = new FileStream(srcXML, FileMode.Open);
                    string contents;
                    using (var sr = new StreamReader(fs0))
                    {
                        contents = sr.ReadToEnd();
                    }

                    writer.WriteRaw(contents);
                    writer.WriteEndElement(); //End Body


                    writer.WriteEndElement(); //End Envelope
                }
                               
                XmlDocument document = signDocument(certificate, stream, correlationId);
                envelope = document.OuterXml;
            }

            return envelope;
        }


        static XmlDocument signDocument(X509Certificate2 certificate, MemoryStream stream, String correlationId)
        {
            var signable = Encoding.UTF8.GetString(stream.ToArray());
            XmlDocument doc = new XmlDocument();
            //Preserve white space for readability.
            doc.PreserveWhitespace = true;
            //Load the file.
            doc.LoadXml(signable);

            var signedXml = new SignedSOAPRequest(doc);

            var key = certificate.GetRSAPrivateKey();
            signedXml.SigningKey = key;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data x509data = new KeyInfoX509Data(certificate);
            keyInfo.AddClause(x509data);
            signedXml.KeyInfo = keyInfo;

            Reference reference0 = new Reference();
            reference0.Uri = "#_0";
            var t0 = new XmlDsigExcC14NTransform();
            reference0.AddTransform(t0);
            reference0.DigestMethod = SignedXml.XmlDsigSHA1Url;
            signedXml.AddReference(reference0);
            signedXml.ComputeSignature();
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            XmlNode info = null;
            for (int i = 0; i < xmlDigitalSignature.ChildNodes.Count; i++)
            {
                var node = xmlDigitalSignature.ChildNodes[i];
                if (node.Name == "KeyInfo")
                {
                    info = node;
                    break;
                }
            }
            info.RemoveAll();

            XmlElement securityTokenReference = doc.CreateElement("o", "SecurityTokenReference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            XmlElement reference = doc.CreateElement("o", "Reference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            reference.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
            reference.SetAttribute("URI", "#" + correlationId);
            securityTokenReference.AppendChild(reference);
            info.AppendChild(securityTokenReference);
            var nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("o", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            nsmgr.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");
            var security_node = doc.SelectSingleNode("/s:Envelope/s:Header/o:Security", nsmgr);
            security_node.AppendChild(xmlDigitalSignature);
            return doc;
        }


        public static void Main(string[] args)
        {
            String configFile = args[0];
            if (!File.Exists(configFile)) {
                Console.WriteLine("File not found! ");
                System.Environment.Exit(1);
            }
            config = new ConfigurationBuilder().SetBasePath(Path.GetDirectoryName(configFile)).AddJsonFile(Path.GetFileName(configFile), true, true).Build();
            String srcXML = config["source-xml"];
            if (args.Length>1 && File.Exists(args[1])) {
                srcXML = args[1];
            }

            Console.WriteLine("App Version: " + config["version"]);
            Console.WriteLine("Current Directoty = " + System.IO.Directory.GetCurrentDirectory());
            Uri uri = new Uri(config["endpoint"]); 
            X509Certificate2 clientCertificate = new X509Certificate2(config["client-certificate"], config["certificate-password"], X509KeyStorageFlags.PersistKeySet);
            X509Certificate2 serverCertificate = new X509Certificate2(config["server-certificate"]);
            String envelope = createSOAPRequest(srcXML, clientCertificate);

   
            using (var httpClientHandler = new HttpClientHandler())
            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, uri))
            {
                httpClientHandler.ServerCertificateCustomValidationCallback = (message, certificate, chain, errors) => {
                    Console.WriteLine("HTTP Request Headers: " + message.Headers);
                    Console.WriteLine("Remote Server Identity: " + certificate.Subject);
                    // To disable SSL validation return true.
                    // return true;
                    return certificate.Equals(serverCertificate);
                };
                using (var client = new HttpClient(httpClientHandler))
                {
                    request.Content = new StringContent(envelope, Encoding.UTF8, "application/soap+xml");
                    request.Headers.Add("SOAPAction", config["SOAPAction"]);
                    using (HttpResponseMessage response = client.SendAsync(request).Result)
                    {
                        if (response.IsSuccessStatusCode)
                        {
                            response.Content.ReadAsStringAsync().ContinueWith(task =>
                            {
                                Console.WriteLine("----- Server Response -----");
                                Console.WriteLine(task.Result);
                            }, TaskContinuationOptions.ExecuteSynchronously);
                        }
                    }
                }
               
            }


        }
    }
}
