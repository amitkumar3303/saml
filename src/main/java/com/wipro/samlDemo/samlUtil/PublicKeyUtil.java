package com.wipro.samlDemo.samlUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PublicKeyUtil {

 /**
  * Generates KeyPair specific to given algorithm
  * 
  * @param algorithm
  * @return
  * @throws NoSuchAlgorithmException
  */
 public static KeyPair getKeyPair(String algorithm)
   throws NoSuchAlgorithmException {
  KeyPairGenerator keyPairGenerator = KeyPairGenerator
    .getInstance(algorithm);
  return keyPairGenerator.generateKeyPair();
 }

 /**
  * generate KeyPair from keystore
  * 
  * @param jksFile
  * @param keyStorePassword
  * @param keyPassword
  * @param alias
  * @return
  * @throws Exception
  */
 public static KeyPair getKeyPairFromKeyStore(String jksFile,
   String keyStorePassword, String keyPassword, String alias)
   throws Exception {
  FileInputStream is = new FileInputStream(jksFile);

  KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
  keystore.load(is, keyStorePassword.toCharArray());

  KeyPair pair = null;

  Key key = keystore.getKey(alias, keyPassword.toCharArray());
  if (key instanceof PrivateKey) {
   /* Get certificate of public key */
   Certificate cert = keystore.getCertificate(alias);

   /* Get public key */
   PublicKey publicKey = cert.getPublicKey();

   /* Construct KeyPair object */
   pair = new KeyPair(publicKey, (PrivateKey) key);

  }
  return pair;
 }

 /**
  * Load keystore from given jks file
  * 
  * @param jksFile
  * @param keyStorePassword
  * @return
  * @throws Exception
  */
 public static KeyStore getKeyStore(String jksFile, String keyStorePassword)
   throws Exception {
  FileInputStream is = new FileInputStream(jksFile);

  KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
  keystore.load(is, keyStorePassword.toCharArray());
  return keystore;
 }

 /**
  * Return PublicKey from given KeyPair
  * 
  * @param keyPair
  * @return
  */
 public static PublicKey getPublicKey(KeyPair keyPair) {
  return keyPair.getPublic();
 }

 /**
  * Return PrivateKey from given KeyPair
  * 
  * @param keyPair
  * @return
  */
 public static PrivateKey getPrivateKey(KeyPair keyPair) {
  return keyPair.getPrivate();
 }

 /**
  * Convert key to string.
  * 
  * @param key
  * 
  * @return String representation of key
  */
 public static String keyToString(Key key) {
  /* Get key in encoding format */
  byte encoded[] = key.getEncoded();

  /*
   * Encodes the specified byte array into a String using Base64 encoding
   * scheme
   */
  String encodedKey = Base64.getEncoder().encodeToString(encoded);

  return encodedKey;
 }

 /**
  * Save key to a file
  * 
  * @param key
  *            : key to save into file
  * @param fileName
  *            : File name to store
  */
 public static void saveKey(Key key, String fileName) {
  byte[] keyBytes = key.getEncoded();
  File keyFile = new File(fileName);
  FileOutputStream fOutStream = null;
  try {
   fOutStream = new FileOutputStream(keyFile);
   fOutStream.write(keyBytes);
  } catch (Exception e) {
   e.printStackTrace();
  } finally {
   if (fOutStream != null) {
    try {
     fOutStream.close();
    } catch (IOException e) {
     e.printStackTrace();
    }
   }
  }
 }

 /**
  * Returns the key stored in a file.
  * 
  * @param fileName
  * @return
  * @throws Exception
  */
 public static byte[] readKeyFromFile(String fileName) throws Exception {
  FileInputStream keyfis = new FileInputStream(fileName);
  byte[] key = new byte[keyfis.available()];
  keyfis.read(key);
  keyfis.close();
  return key;
 }

 /**
  * Generates public key from encoded byte array.
  * 
  * @param encoded
  * @param algorithm
  * @return
  * @throws Exception
  */
 public static PublicKey convertArrayToPubKey(byte encoded[],
   String algorithm) throws Exception {
  X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
  KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
  PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

  return pubKey;
 }

 /**
  * Generates private key from encoded byte array.
  * 
  * @param encoded
  * @param algorithm
  * @return
  * @throws Exception
  */
 public static PrivateKey convertArrayToPriKey(byte encoded[],
   String algorithm) throws Exception {
  PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
  KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
  PrivateKey priKey = keyFactory.generatePrivate(keySpec);
  return priKey;
 }

 /**
  * Generate X509Certificate from keystore, alias and password
  * 
  * @param ks
  * @param alias
  * @param keyPassword
  * @return
  * @throws Exception
  */
 public static X509Certificate getX509Certificate(KeyStore ks, String alias,
   String keyPassword) throws Exception {
  KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks
    .getEntry(
      alias,
      new KeyStore.PasswordProtection(keyPassword
        .toCharArray()));

  X509Certificate certificate = (X509Certificate) pkEntry
    .getCertificate();

  return certificate;
 }

}