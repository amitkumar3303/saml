package com.wipro.samlDemo.samlUtil;
import java.util.List;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.saml.ext.bean.AuthenticationStatementBean;
import org.apache.ws.security.saml.ext.bean.ConditionsBean;
import org.apache.ws.security.saml.ext.bean.KeyInfoBean;
import org.apache.ws.security.saml.ext.bean.SubjectBean;
import org.apache.ws.security.saml.ext.bean.SubjectConfirmationDataBean;
import org.apache.ws.security.saml.ext.builder.SAML2ComponentBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.xml.security.SecurityException;

public class SAMLUtil {
 /**
  * Method returns Assertion instacne
  * 
  * @return Assertion instance
  */
 public static Assertion getAssertion() {
  return SAML2ComponentBuilder.createAssertion();
 }

 /**
  * Method returns Subject instance
  * 
  * @param subjectBean
  *            Represents SAML subject
  * @return Subject instance
  * @throws SecurityException
  * @throws WSSecurityException
  */
 public static Subject getSubject(SubjectBean subjectBean)
   throws SecurityException, WSSecurityException {
  return SAML2ComponentBuilder.createSaml2Subject(subjectBean);
 }

 /**
  * Method returns SubjectConfirmation instance
  * 
  * @param method
  *            can be any of following two values.
  * 
  *            can be urn:oasis:names:tc:SAML:2.0:cm:holder-of-key
  *            urn:oasis:names:tc:SAML:2.0:cm:sender-vouches (or)
  *            urn:oasis:names:tc:SAML:2.0:cm:bearer
  * 
  * @param subjectConfirmationData
  * @return
  */
 public static SubjectConfirmation getSubjectConfirmation(String method,
   SubjectConfirmationData subjectConfirmationData) {
  return SAML2ComponentBuilder.createSubjectConfirmation(method,
    subjectConfirmationData);

 }

 /**
  * Method returns SubjectConfirmationData instance.
  * 
  * @param subjectConfirmationDataBean
  *            Represents SAML SubjectConfirmationData
  * @param keyInfoBean
  *            Represents a KeyInfo structure that will be embedded in a SAML
  *            Subject
  * @return SubjectConfirmationData instance.
  * @throws SecurityException
  * @throws WSSecurityException
  */
 public static SubjectConfirmationData getSubjectConfirmationData(
   SubjectConfirmationDataBean subjectConfirmationDataBean,
   KeyInfoBean keyInfoBean) throws SecurityException,
   WSSecurityException {
  return SAML2ComponentBuilder.createSubjectConfirmationData(
    subjectConfirmationDataBean, keyInfoBean);
 }

 /**
  * Method returns Conditions instance.
  * 
  * @param conditionsBean
  *            Represents a SAML Conditions object
  * @return Conditions instance
  */
 public static Conditions getConditionsElement(ConditionsBean conditionsBean) {
  return SAML2ComponentBuilder.createConditions(conditionsBean);
 }

 /**
  * Return List of AuthnStatement objects.
  * 
  * @param authBeans
  *            : Represents list of AuthenticationStatementBean objects.
  *            AuthenticationStatementBean represents the raw data required
  *            to create a SAML v1.1 or v2.0 authentication statement
  * @return List of AuthnStatement objects
  */
 public static List<AuthnStatement> getAuthStatement(
   List<AuthenticationStatementBean> authBeans) {
  return SAML2ComponentBuilder.createAuthnStatement(authBeans);
 }
}