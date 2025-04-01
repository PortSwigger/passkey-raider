package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.utilities.Base64DecodingOptions;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.URLUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;
import com.webauthn4j.util.MessageDigestUtil;

import java.lang.reflect.Type;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.core.HighlightColor.BLUE;

class MyProxyHttpRequestHandler implements ProxyRequestHandler {

	private final SettingForm settingForm;
	private final MontoyaApi api;
	private final Util util;
	private final Gson gsonPrettyPrinting;
	private final Base64Utils base64Utils;
	private final URLUtils urlUtils;


	MyProxyHttpRequestHandler(SettingForm settingForm, MontoyaApi api)
	{
		this.settingForm = settingForm;
		this.api = api;
		this.util = new Util(api);
		gsonPrettyPrinting = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();
		base64Utils = api.utilities().base64Utils();
		urlUtils = api.utilities().urlUtils();
	}

	@Override
	public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
		try {
			if (interceptedRequest.url().equalsIgnoreCase(settingForm.registrationURL)) {
				/*
				- decode
				- change pub key
				- encode
				*/
				String requestBody = interceptedRequest.bodyToString();

				Matcher matcherAttestationObject = settingForm.registrationCompiledRegexAttestationObject.matcher(requestBody);

				if (matcherAttestationObject.find()) {
					String attestationObjectValue = matcherAttestationObject.group(1);

					// check attestationObjectValue URL encoded
					String attestationObject_URLDecoded = settingForm.isRegisterAttestationObjectURLEncoded ? urlUtils.decode(attestationObjectValue) : attestationObjectValue;

					// convert attestationObjectValue to Base64Url
					Map<String, Object> attestationObject = util.decodeAttestationObject(Util.base64ToBase64Url(attestationObject_URLDecoded));

					Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
					Map<String, Object> coseKey = gsonPrettyPrinting.fromJson(settingForm.coseKeyJsonString, mapType);

					((Map<String, Object>) ((Map<String, Object>) attestationObject.get("authenticatorData")).get("attestedCredentialData")).put("coseKey", coseKey);

					String modifiedAttestationObjectB64URL = util.encodeAttestationObject(attestationObject);

					// check attestationObjectValue Base64Url
					String modifiedAttestationObjectB64 = settingForm.isRegisterAttestationObjectBase64URL ? modifiedAttestationObjectB64URL : Util.base64UrlToBase64(modifiedAttestationObjectB64URL);

					// check attestationObjectValue URL encoded
					String attestationObject_URLEncoded = settingForm.isRegisterAttestationObjectURLEncoded ? urlUtils.encode(modifiedAttestationObjectB64) : modifiedAttestationObjectB64;

					requestBody = requestBody.replaceAll(Pattern.quote(attestationObjectValue), attestationObject_URLEncoded);

					return ProxyRequestReceivedAction.continueWith(interceptedRequest.withBody(requestBody), interceptedRequest.annotations().withHighlightColor(BLUE));
				}
			} else if (interceptedRequest.url().equalsIgnoreCase(settingForm.authenticationURL)) {
				return ProxyRequestReceivedAction.continueWith(interceptedRequest, interceptedRequest.annotations().withHighlightColor(BLUE));
			}
		} catch (Exception e) {
			api.logging().logToOutput("Error handleRequestReceived: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return ProxyRequestReceivedAction.continueWith(interceptedRequest);
	}

	@Override
	public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
		try {
			if (interceptedRequest.url().equalsIgnoreCase(settingForm.authenticationURL)) {
				String requestBody = interceptedRequest.bodyToString();

				Matcher matcherClientDataJSON = settingForm.authenticationCompiledRegexClientDataJSON.matcher(requestBody);
				Matcher matcherAuthenticatorData = settingForm.authenticationCompiledRegexAuthenticatorData.matcher(requestBody);
				Matcher matcherSignature = settingForm.authenticationCompiledRegexSignature.matcher(requestBody);

				if (matcherClientDataJSON.find() && matcherAuthenticatorData.find() && matcherSignature.find()) {
					String clientDataJSONValue = matcherClientDataJSON.group(1);
					String authenticatorDataValue = matcherAuthenticatorData.group(1);
					String signatureValue = matcherSignature.group(1);

					// check URL encoded
					String clientDataJSON_URLDecoded = settingForm.isAuthenClientDataJsonURLEncoded ? urlUtils.decode(clientDataJSONValue) : clientDataJSONValue;
					String authenticatorData_URLDecoded = settingForm.isAuthenAuthenticatorDataURLEncoded ? urlUtils.decode(authenticatorDataValue) : authenticatorDataValue;

					// sign
					byte[] clientDataJSONBytes = base64Utils.decode(Util.base64ToBase64Url(clientDataJSON_URLDecoded), Base64DecodingOptions.URL).getBytes();
					byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSONBytes);
					byte[] authenticatorDataBytes = base64Utils.decode(Util.base64ToBase64Url(authenticatorData_URLDecoded), Base64DecodingOptions.URL).getBytes();
					byte[] data = ByteBuffer.allocate(authenticatorDataBytes.length + clientDataHash.length).put(authenticatorDataBytes).put(clientDataHash).array();
					String modifiedSignatureB64URL = util.calculateSignature(settingForm.coseKey, data);
					String modifiedSignatureB64 = settingForm.isAuthenSignatureBase64URL ? modifiedSignatureB64URL : Util.base64UrlToBase64(modifiedSignatureB64URL);

					// check URL encoded
					String modifiedSignatureB64_URLEncoded = settingForm.isAuthenSignatureURLEncoded ? urlUtils.encode(modifiedSignatureB64) : modifiedSignatureB64;

					requestBody = requestBody.replaceAll(Pattern.quote(signatureValue), modifiedSignatureB64_URLEncoded);
					return ProxyRequestToBeSentAction.continueWith(interceptedRequest.withBody(requestBody));
				}
			}
		} catch (Exception e) {
			api.logging().logToOutput("Error handleRequestToBeSent: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
	}
}

