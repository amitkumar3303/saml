package com.wipro.samlDemo.controller;

import org.opensaml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.wipro.samlDemo.util.Utilily;

@RestController
public class SamlToken2 {

	@Autowired
	Utilily utility;
	
	@Autowired
	ResponseValidator responseValidator;

	@GetMapping(value = "/soap")
	public Response samlToken2(Response response) throws Exception {

		boolean validationResult = responseValidator.validateSignature(response);
		if (validationResult) {
			// call soap service

		} else {
			// return validation fail
		}

		return response;

	}


}
