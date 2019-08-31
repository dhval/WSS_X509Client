using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.Xml;
using System.Xml;

/*
 * The material embodied in this software is provided to you "as-is" and without warranty of any kind, express,
 * implied or otherwise, including without limitation, any warranty of fitness for a particular purpose. 
 *
 * Copyright (c) 2018 - Dhval Mudawal
 */

namespace WSClient
{
    public class SignedSOAPRequest : SignedXml
    {
        public SignedSOAPRequest(XmlDocument xml) : base(xml)
        {
        }

        public SignedSOAPRequest(XmlElement xmlElement)
            : base(xmlElement)
        {
        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            // check to see if it's a standard ID reference
            XmlElement idElem = base.GetIdElement(document, idValue);

            if (idElem == null)
            {
                XmlNamespaceManager nsManager = new XmlNamespaceManager(document.NameTable);
                nsManager.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

                idElem = document.SelectSingleNode("//*[@wsu:Id=\"" + idValue + "\"]", nsManager) as XmlElement;
            }

            return idElem;
        }
    }
}
