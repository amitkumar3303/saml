package com.wipro.samlDemo.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Component
@Configuration
public class Utilily {

	
	
	//public static final String JKS_FILE ="src\\main\\resources\\SAML\\keystore.jks";
			//"src\\main\\java\\com\\wipro\\samlDemo\\util\\keystore.jks";
	//public static final  String KEY_STORE_PASSWORD = "password123";
	//public static final String KEY_PASSWORD = "password123";
//	public static final String ALIAS = "certificate1";
	

	    @Value("${server.ssl.key-alias}")
	    String keyAlias;

	    @Value("${server.ssl.key-store-password}")
	    String keyStorePassword;

	    @Value("${server.port}")
	    String port;

	    @Value("${server.ssl.key-store}")
	    String keyStoreFilePath;

	    @Value("${server.ssl.key-password}")
	    String keyPassword;

		public String getKeyAlias() {
			return keyAlias;
		}

		public String getKeyStorePassword() {
			return keyStorePassword;
		}

		public String getPort() {
			return port;
		}

		public String getKeyStoreFilePath() {
			return keyStoreFilePath;
		}

		public String getKeyPassword() {
			return keyPassword;
		}

	

}
