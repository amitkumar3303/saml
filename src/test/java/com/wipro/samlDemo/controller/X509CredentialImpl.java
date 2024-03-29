package com.wipro.samlDemo.controller;

import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;

/**
 * X509Credential implementation for signature verification of self issued tokens. The key is
 * constructed from modulus and exponent
 */
public class X509CredentialImpl implements X509Credential {

    private PublicKey publicKey = null;
    private X509Certificate signingCert = null;

    /**
     * The key is constructed form modulus and exponent.
     *
     * @param modulus
     * @param publicExponent
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public X509CredentialImpl(BigInteger modulus, BigInteger publicExponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(spec);
    }

    public X509CredentialImpl(X509Certificate cert) {
        publicKey = cert.getPublicKey();
        signingCert = cert;
    }

    /**
     * Retrieves the publicKey
     */
    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public X509Certificate getSigningCert() {
        return signingCert;
    }

    // ********** Not implemented **************************************************************

    @Override
    public X509Certificate getEntityCertificate() {
        return null;
    }

    @Override
    public Collection<X509CRL> getCRLs() {
        return new ArrayList<>();
    }

    @Override
    public Collection<X509Certificate> getEntityCertificateChain() {
        return new ArrayList<>();
    }

    @Override
    public CredentialContextSet getCredentalContextSet() {
        return null;
    }

    @Override
    public Class<? extends Credential> getCredentialType() {
        return null;
    }

    @Override
    public String getEntityId() {
        return null;
    }

    @Override
    public Collection<String> getKeyNames() {
        return new ArrayList<>();
    }

    @Override
    public PrivateKey getPrivateKey() {
        return null;
    }

    @Override
    public SecretKey getSecretKey() {
        return null;
    }

    @Override
    public UsageType getUsageType() {
        return null;
    }
}