/*******************************************************************************
* Copyright (c) 2006-2019 Massachusetts General Hospital and Partners Healthcare
* All rights reserved.
* 
******************************************************************************/
/*
 * Contributors:
 * 		Yanbing Wang
 * 
 */
package edu.harvard.i2b2.pm.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.Hashtable;
import java.util.Timer;
    
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.httpclient.HttpClient;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCredentialResolverFactory;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.commons.codec.binary.Base64;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.harvard.i2b2.common.exception.I2B2Exception;

public class SecurityAuthenticationSAML  implements SecurityAuthentication {
	protected final Log log = LogFactory.getLog(getClass());

	@Override
	public boolean validateUser(String username, String password, Hashtable params) throws Exception {
		
		// use password parameter to pass in SAML response;
		X509Credential credential;
		Signature sig;
		try {
			String responseMessage = password; 
			Base64 base64 = new Base64();
			
			byte[] base64DecodedResponse = base64.decode(responseMessage.getBytes()); 
			
			log.info ("okta user: " + username);
// *   1. parse the base64 encoded response into a Java object
			if (password.trim().length() < 1) {
				log.error("saml response is empty");
				throw new I2B2Exception("saml response is empty");
			} else {
				log.info("Part of saml response:" + password.substring(0, 70));
			}
			
			if (base64DecodedResponse.length < 1) {
				log.error("base64DecodedResponse is empty");
				throw new I2B2Exception("base64DecodedResponse is empty");
			} else {
				log.info("base64DecodedResponse.length = " + base64DecodedResponse.length);
			}

			DefaultBootstrap.bootstrap();
			// create a DOM Element object out of the response string.
			
			ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);

			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

			Document document = docBuilder.parse(is);
			Element element = document.getDocumentElement();

			
			//unmarshall the element.

			//DefaultBootstrap.bootstrap();

			UnmarshallerFactory unmarshallerFactory = org.opensaml.xml.Configuration.getUnmarshallerFactory();

			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

			XMLObject responseXmlObj = unmarshaller.unmarshall(element);

			
			// Casting the response to the SAML 2.0 Response message.
			Response response = (Response) responseXmlObj;
			
 //  2. Validate the SAML assertion is signed by trusted IdP server and the status is success.
			
			// read the Assertion. This Response with one Assertion
			Assertion assertion = response.getAssertions().get(0);

			//read the Subject name (Subject is what was authenticated at the IDP)
			String subject = assertion.getSubject().getNameID().getValue();

			// read the issuer (Issuer is the IDP who issued the Response object)
			String issuer = assertion.getIssuer().getValue();

			//read the status
			String statusCode = response.getStatus().getStatusCode().getValue();
			
			if (!statusCode.equalsIgnoreCase(StatusCode.SUCCESS_URI)) {
				return false;
			}
					
			log.info ("status code: " + statusCode);
			
//		 *  2b. validate the signature.
			
			//read the audience (To whom the Response was issued)
			String audience = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI();
							
//		    load idP metadata using http or from a local file?		
			AbstractMetadataProvider idpMetadataProvider;
			String metadataUrl = (String) params.get("IdP_metadata_url");
			
			if (metadataUrl == null) {
			    throw new I2B2Exception("No metadata URI set for SAML");
			}

			Timer timer = new Timer();
			final HttpClient client = new HttpClient();
			if (metadataUrl.startsWith("http:") || metadataUrl.startsWith("https:")) {
			    idpMetadataProvider = new HTTPMetadataProvider(timer, client, metadataUrl);  //  (metadataUrl, requestTimeout * 1000);
			} else { // file based
				File metadataFile = new File(metadataUrl);
			    idpMetadataProvider = new FilesystemMetadataProvider(timer, metadataFile);
			}
			
			idpMetadataProvider.setRequireValidMetadata(true);
			idpMetadataProvider.setParserPool(new BasicParserPool());
			idpMetadataProvider.initialize();
			log.info(idpMetadataProvider.getMetadata().toString());
//		        timer.scheduleAtFixedRate(new MetadataRefreshTask(), 0, 5 * 1000);
			MetadataCredentialResolverFactory credentialResolverFactory = MetadataCredentialResolverFactory.getFactory();
			MetadataCredentialResolver credentialResolver = credentialResolverFactory.getInstance(idpMetadataProvider);
			
			CriteriaSet criteriaSet = new CriteriaSet();
			criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
			criteriaSet.add(new EntityIDCriteria((String) params.get("IdP_entity_id")));  // IPDEntityId to be provided by organization
				    
			credential = (X509Credential)credentialResolver.resolveSingle(criteriaSet);

			// first validate the message with a SAML profile validator to ensure that the signature follows the standard for XML signatures
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator(); 
			sig = response.getSignature();
			profileValidator.validate(sig);
			SignatureValidator validator = new SignatureValidator(credential);
			try {
				validator.validate(sig);
				log.info("SAML Response signature validated!");
			} catch (ValidationException e) {
	            throw new I2B2Exception("Signature validation failed for SAML Response");
	        }
		} catch (Exception e) {
			log.error(e.getMessage());
			throw new I2B2Exception(e.getMessage());
		}

		// then perform the cryptography validation of the signature

		return true;
	}

}
