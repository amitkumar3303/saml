package com.wipro.samlDemo.controller;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.saml.ext.bean.AudienceRestrictionBean;
import org.apache.ws.security.saml.ext.bean.AuthenticationStatementBean;
import org.apache.ws.security.saml.ext.bean.ConditionsBean;
import org.apache.ws.security.saml.ext.bean.ProxyRestrictionBean;
import org.apache.ws.security.saml.ext.bean.SubjectBean;
import org.apache.ws.security.saml.ext.bean.SubjectConfirmationDataBean;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;

import com.wipro.samlDemo.samlUtil.PublicKeyUtil;
import com.wipro.samlDemo.samlUtil.SAMLUtil;
import com.wipro.samlDemo.util.Utilily;

@RestController
public class SamlToken {
	
	@Autowired
	Utilily utility;

	@GetMapping(value="/saml")
	public String samlToken() throws Exception {
		
		//utility.get
		/* Initializes the OpenSAML library */
		DefaultBootstrap.bootstrap();

		/* Create assertion */
		Assertion assertion = SAMLUtil.getAssertion();

		/* Add elements to assertion */
		addSubjectToAssertion(assertion);
		addConditionsToAssertion(assertion);
		addAuthenticationStatement(assertion);
		addSignatureToAssertion(assertion);

		/* Create Response object */
		Response resp = (Response) Configuration.getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME)
				.buildObject(Response.DEFAULT_ELEMENT_NAME);

		/* Add assertion to response */
		resp.getAssertions().add(assertion);
		// addSignatureToResponse(resp);

		ResponseMarshaller marshaller = new ResponseMarshaller();
		Element plain = marshaller.marshall(resp);

		String samlResponse = XMLHelper.nodeToString(plain);
	
		//System.out.println(samlResponse);
		return samlResponse;	
		
	}

	public  void addSubjectToAssertion(Assertion assertion) throws SecurityException, WSSecurityException {
		/* Create and add subject to assertion */
		SubjectBean subjectBean = new SubjectBean();
		subjectBean.setSubjectName("Amit Kumar");
		Subject subject = SAMLUtil.getSubject(subjectBean);

		/* Create SubjectConfirmation Object */
		// Create SubjectConfirmationDataBean
		SubjectConfirmationDataBean subjectConfirmationDataBean = new SubjectConfirmationDataBean();
		subjectConfirmationDataBean.setAddress("123.124.125.126");
		DateTime dateTime = new DateTime();
		DateTime afterTime = dateTime.plusMinutes(5);
		subjectConfirmationDataBean.setNotAfter(afterTime);
		subjectConfirmationDataBean.setNotBefore(dateTime);
		subjectConfirmationDataBean.setRecipient("http://abc.com");

		// Initialize SubjectConfirmationData
		SubjectConfirmationData subjectConfirmationData = SAMLUtil
				.getSubjectConfirmationData(subjectConfirmationDataBean, null);

		// Initialize SubjectConfirmation
		SubjectConfirmation subjectConfirmation = SAMLUtil
				.getSubjectConfirmation("urn:oasis:names:tc:SAML:2.0:cm:bearer", subjectConfirmationData);

		subject.getSubjectConfirmations().add(subjectConfirmation);
		assertion.setSubject(subject);

	}

	public  void addConditionsToAssertion(Assertion assertion) {
		DateTime dateTime = new DateTime();
		/* Create and add Conditions element to assertion */
		// Initialize ConditionsBean
		ConditionsBean conditionsBean = new ConditionsBean();
		DateTime aftersserTime = dateTime.plusMinutes(10);
		conditionsBean.setNotAfter(aftersserTime);
		conditionsBean.setNotBefore(dateTime);
		conditionsBean.setOneTimeUse(true);
		conditionsBean.setTokenPeriodMinutes(5);

		// Create and add audience restriction to conditionsBean
		List<AudienceRestrictionBean> audienceRestrictions = new ArrayList<>();

		AudienceRestrictionBean bean = new AudienceRestrictionBean();
		bean.getAudienceURIs().add("Engineers");
		bean.getAudienceURIs().add("Managers");
		bean.getAudienceURIs().add("Testers");

		audienceRestrictions.add(bean);

		conditionsBean.setAudienceRestrictions(audienceRestrictions);

		// Create and add ProxyRestrictionBean to conditions
		ProxyRestrictionBean proxyRestrictionBean = new ProxyRestrictionBean();
		proxyRestrictionBean.setCount(3);
		conditionsBean.setProxyRestriction(proxyRestrictionBean);

		Conditions conditions = SAMLUtil.getConditionsElement(conditionsBean);
		assertion.setConditions(conditions);

	}

	public  void addAuthenticationStatement(Assertion assertion) {
		/* Create and add Authentication statement to assertion */
		List<AuthenticationStatementBean> authBeans = new ArrayList<>();

		AuthenticationStatementBean authBean = new AuthenticationStatementBean();
		DateTime authTime = new DateTime();
		authBean.setAuthenticationInstant(authTime);
		authBean.setAuthenticationMethod("SAML token-based authentication");
		authBean.setSessionIndex("session_11");

		authBeans.add(authBean);

		List<AuthnStatement> authStatements = SAMLUtil.getAuthStatement(authBeans);

		assertion.getAuthnStatements().addAll(authStatements);
	}

	public  void addSignatureToResponse(Response resp) throws Exception {
		Signature signature = getSignature();
		resp.setSignature(signature);

		try {
			Configuration.getMarshallerFactory().getMarshaller(resp).marshall(resp);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}

		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}

	public  Signature getSignature() throws Exception {
		
		KeyPair keyPair = PublicKeyUtil.getKeyPairFromKeyStore(utility.getKeyStoreFilePath(),utility.getKeyStorePassword(),utility.getKeyPassword(), utility.getKeyAlias());

		PrivateKey pk = keyPair.getPrivate();

		KeyStore ks = PublicKeyUtil.getKeyStore(utility.getKeyStoreFilePath(), utility.getKeyStorePassword());

		X509Certificate certificate = PublicKeyUtil.getX509Certificate(ks, utility.getKeyAlias(), utility.getKeyStorePassword());

		BasicX509Credential signingCredential = new BasicX509Credential();
		signingCredential.setEntityCertificate(certificate);
		signingCredential.setPrivateKey(pk);

		Signature signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(signingCredential);

		// This is also the default if a null SecurityConfiguration is specified
		SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();

		try {
			SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
		} catch (SecurityException e) {
			e.printStackTrace();
		}

		return signature;
	}

	public  void addSignatureToAssertion(Assertion assertion) throws Exception {

		Signature signature = getSignature();

		assertion.setSignature(signature);

		try {
			Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}

		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}

}
