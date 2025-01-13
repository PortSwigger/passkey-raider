/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp;


import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.core.HighlightColor.BLUE;

class MyProxyHttpRequestHandler implements ProxyRequestHandler {

	private final SettingForm settingForm;
	private final MontoyaApi api;
	private final Util util;
	Gson gsonPrettyPrinting;

	MyProxyHttpRequestHandler(SettingForm settingForm, MontoyaApi api)
	{
		this.settingForm = settingForm;
		this.api = api;
		this.util = new Util(api);
		gsonPrettyPrinting = new GsonBuilder().setPrettyPrinting().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();
	}

	@Override
	public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
		//Drop all post requests
        /*if (interceptedRequest.method().equals("POST")) {
            return ProxyRequestReceivedAction.drop();
        }*/



        /*if (interceptedRequest.url().equalsIgnoreCase(settingForm.registrationURL) || interceptedRequest.url().equalsIgnoreCase(settingForm.authenticationURL)) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest, interceptedRequest.annotations().withHighlightColor(BLUE));
        }*/


		if (interceptedRequest.url().equalsIgnoreCase(settingForm.registrationURL)) {
            /*
            - decode
            - change pub key
            - encode
            */
			String requestBody = interceptedRequest.bodyToString();

			Pattern patternAttestationObject = Pattern.compile(settingForm.registrationRegexAttestationObject);
			Matcher matcherAttestationObject = patternAttestationObject.matcher(requestBody);

			if (matcherAttestationObject.find()) {
				String attestationObjectValue = matcherAttestationObject.group(1);
				api.logging().logToOutput("\n============= " + settingForm.registrationURL + " =============");
				api.logging().logToOutput("attestationObjectValue: " + attestationObjectValue);

				Map<String, Object> attestationObject = util.decodeAttestationObject(attestationObjectValue);

				Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
				Map<String, Object> coseKey = gsonPrettyPrinting.fromJson(settingForm.coseKeyJsonString, mapType);

				((Map<String, Object>) ((Map<String, Object>) attestationObject.get("authenticatorData")).get("attestedCredentialData")).put("coseKey", coseKey);

				String modifiedAttestationObjectB64 = util.encodeAttestationObject(attestationObject);
				requestBody = requestBody.replaceAll(attestationObjectValue, modifiedAttestationObjectB64);


                /*Map<String, Object> authenticatorDataMap = (Map<String, Object>) attestationObject.get("authenticatorData");
                Map<String, Object> attestedCredentialDataMap = (Map<String, Object>) authenticatorDataMap.get("attestedCredentialData");
                Map<String, Object> coseKeyMap = (Map<String, Object>) attestedCredentialDataMap.get("coseKey");*/

				return ProxyRequestReceivedAction.continueWith(interceptedRequest.withBody(requestBody), interceptedRequest.annotations().withHighlightColor(BLUE));
			}
		} else if (interceptedRequest.url().equalsIgnoreCase(settingForm.authenticationURL)) {
			return ProxyRequestReceivedAction.continueWith(interceptedRequest, interceptedRequest.annotations().withHighlightColor(BLUE));
		}



		//If the content type is json, highlight the request and follow burp rules for interception
        /*if (interceptedRequest.contentType() == JSON) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest, interceptedRequest.annotations().withHighlightColor(RED));
        }*/

		//Intercept all other requests
		//return ProxyRequestReceivedAction.intercept(interceptedRequest);

		return ProxyRequestReceivedAction.continueWith(interceptedRequest);

	}

	@Override
	public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
		//Do nothing with the user modified request, continue as normal.
		api.logging().logToOutput("\n============= handleRequestToBeSent =============");

		return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
	}
}

