package com.wipro.samlDemo.controller;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import com.wipro.samlDemo.controller.X509CredentialImpl;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.w3c.dom.Element;

import com.wipro.samlDemo.samlUtil.PublicKeyUtil;
import com.wipro.samlDemo.util.Utilily;

@RunWith(SpringRunner.class)
@SpringBootTest
public class TestController {

	@Autowired
	SamlToken samlToken;

	@Autowired
	Utilily utilily;

	@Test
	public void testCont() throws Exception {

		Response responseCont = samlToken.samlToken1();

		ResponseMarshaller marshaller = new ResponseMarshaller();
		Element plain = marshaller.marshall(responseCont);

		String samlResponse = XMLHelper.nodeToString(plain);
		System.out.println(samlResponse);
		Signature signValue = samlToken.getSignature();
		boolean booleanValue = validateSignature(signValue);
		System.out.println(booleanValue);

	}

	/**
	 * Create basic X509 credentials using server configuration
	 *
	 * @return basicX509Credential
	 * @throws Exception
	 */
	private BasicX509Credential createBasicCredentials() throws Exception {

		PrivateKey issuerPK = null;
		X509Certificate certificate = null;
		// Certificate certificate = null;
		// ServerConfiguration serverConfig = ServerConfiguration.getInstance();
		String ksPassword = utilily.getKeyStorePassword();// serverConfig.getFirstProperty("Security.KeyStore.Password");
		String ksLocation = utilily.getKeyStoreFilePath();// serverConfig.getFirstProperty("Security.KeyStore.Location");
		String keyAlias = utilily.getKeyAlias();// serverConfig.getFirstProperty("Security.KeyStore.KeyAlias");
		// String ksType =utilily.getKeyAlias();//
		// serverConfig.getFirstProperty("Security.KeyStore.Type");
		String privateKeyPassword = utilily.getKeyPassword();// serverConfig.getFirstProperty("Security.KeyStore.KeyPassword");

		try {
			FileInputStream fis = new FileInputStream(ksLocation);
			BufferedInputStream bis = new BufferedInputStream(fis);
			// KeyStore keyStore = KeyStore.getInstance(ksType);

			KeyStore ks = PublicKeyUtil.getKeyStore(utilily.getKeyStoreFilePath(), utilily.getKeyStorePassword());
			// keyStore.load(bis, ksPassword.toCharArray());
			bis.close();
			KeyPair keyPair = PublicKeyUtil.getKeyPairFromKeyStore(utilily.getKeyStoreFilePath(),
					utilily.getKeyStorePassword(), utilily.getKeyPassword(), utilily.getKeyAlias());
			PrivateKey pk = keyPair.getPrivate();

			certificate = PublicKeyUtil.getX509Certificate(ks, utilily.getKeyAlias(), utilily.getKeyPassword());
			// issuerPK = (PrivateKey) keyStore.getKey(keyAlias,
			// privateKeyPassword.toCharArray());
			// certificate = keyStore.getCertificate(keyAlias);

		} catch (KeyStoreException e) {
			e.printStackTrace();
			// log.error("Error in getting a keystore.", e);
		} catch (FileNotFoundException e) {
			// log.error("Error in reading the keystore file from given the location.", e);
		} catch (CertificateException e) {
			// log.error("Error in creating a X.509 certificate.", e);
		} catch (NoSuchAlgorithmException e) {
			// log.error("Error in loading the keystore.", e);
		} catch (IOException e) {
			// log.error("Error in reading keystore file.", e);
		} catch (UnrecoverableKeyException e) {
			// log.error("Error in getting the private key.", e);
		}

		BasicX509Credential basicCredential = new BasicX509Credential();
		basicCredential.setEntityCertificate((java.security.cert.X509Certificate) certificate);
		basicCredential.setPrivateKey(issuerPK);

		return basicCredential;
	}

	private X509CredentialImpl getPublicX509CredentialImpl() throws Exception {

		X509CredentialImpl credentialImpl = null;
		// load the default public cert using the configuration in carbon.xml
		java.security.cert.X509Certificate cert = createBasicCredentials().getEntityCertificate();
		credentialImpl = new X509CredentialImpl(cert);
		return credentialImpl;

	}

	private boolean validateSignature(Signature signature) throws Exception {

		boolean isSignatureValid = false;

		try {
			SignatureValidator validator = new SignatureValidator(getPublicX509CredentialImpl());
			validator.validate(signature);
			isSignatureValid = true;
		} catch (ValidationException e) {
			e.printStackTrace();
		}

		return isSignatureValid;
	}

}
