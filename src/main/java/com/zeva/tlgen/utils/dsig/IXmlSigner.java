package com.zeva.tlgen.utils.dsig;

import org.w3c.dom.Document;



public interface IXmlSigner {
	
	Document signDocument(Document xmlDocument) throws Exception;
}
