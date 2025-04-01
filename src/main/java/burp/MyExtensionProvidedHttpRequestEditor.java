package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.utilities.Base64DecodingOptions;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.Base64EncodingOptions;
import burp.api.montoya.utilities.URLUtils;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;

import java.nio.ByteBuffer;
import java.util.*;
import java.lang.reflect.Type;
import java.awt.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.core.ByteArray.byteArray;

class MyExtensionProvidedHttpRequestEditor implements ExtensionProvidedHttpRequestEditor
{
	private final RawEditor requestEditor;
	private HttpRequestResponse requestResponse;
	private final SettingForm settingForm;
	private final MontoyaApi api;
	private final Base64Utils base64Utils;
	private final URLUtils urlUtils;
	private final Gson gsonPrettyPrinting;
	private final Util util;

	private final AuthenticatorDataConverter authenticatorDataConverter;

	MyExtensionProvidedHttpRequestEditor(SettingForm settingForm, MontoyaApi api, EditorCreationContext creationContext)
	{
		this.settingForm = settingForm;
		this.api = api;
		this.util = new Util(api);
		base64Utils = api.utilities().base64Utils();
		urlUtils = api.utilities().urlUtils();
		ObjectConverter objectConverter = new ObjectConverter();
		authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);

		gsonPrettyPrinting = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();

		if (creationContext.editorMode() == EditorMode.READ_ONLY)
		{
			requestEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
		}
		else {
			requestEditor = api.userInterface().createRawEditor();
		}
	}

	@Override
	public HttpRequest getRequest()
	{
		HttpRequest request = null;
		try {
			if (requestEditor.isModified())
			{
				Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
				Map<String, Object> textEditorContent = gsonPrettyPrinting.fromJson(String.valueOf(requestEditor.getContents()), mapType);

				String requestBody = requestResponse.request().bodyToString();
				util.logPrettyJson("textEditorContent: ", textEditorContent);

				if (requestResponse.url().equalsIgnoreCase(settingForm.registrationURL)) {
					Matcher matcherClientDataJSON = settingForm.registrationCompiledRegexClientDataJSON.matcher(requestBody);
					Matcher matcherAttestationObject = settingForm.registrationCompiledRegexAttestationObject.matcher(requestBody);

					if (matcherClientDataJSON.find() && matcherAttestationObject.find()) {
						String clientDataJSONValue = matcherClientDataJSON.group(1);
						String attestationObjectValue = matcherAttestationObject.group(1);

						@SuppressWarnings("unchecked") Map<String, Object> clientDataJSON = (Map<String, Object>) textEditorContent.get("clientDataJSON");
						@SuppressWarnings("unchecked") Map<String, Object> attestationObject = (Map<String, Object>) textEditorContent.get("attestationObject");

						String modifiedClientDataJSONB64URL = util.encodeClientDataJSON(clientDataJSON);
						String modifiedAttestationObjectB64URL = util.encodeAttestationObject(attestationObject);

						// check Base64Url
						String modifiedClientDataJSONB64 = settingForm.isRegisterClientDataJsonBase64URL ? modifiedClientDataJSONB64URL : Util.base64UrlToBase64(modifiedClientDataJSONB64URL);
						String modifiedAttestationObjectB64 = settingForm.isRegisterAttestationObjectBase64URL ? modifiedAttestationObjectB64URL : Util.base64UrlToBase64(modifiedAttestationObjectB64URL);

						// check URL encoded
						String modifiedClientDataJSONB64_URLEncoded = settingForm.isRegisterClientDataJsonURLEncoded ? urlUtils.encode(modifiedClientDataJSONB64) : modifiedClientDataJSONB64;
						String modifiedAttestationObjectB64_URLEncoded = settingForm.isRegisterAttestationObjectURLEncoded ? urlUtils.encode(modifiedAttestationObjectB64) : modifiedAttestationObjectB64;

						requestBody = requestBody.replaceAll(Pattern.quote(clientDataJSONValue), modifiedClientDataJSONB64_URLEncoded);
						requestBody = requestBody.replaceAll(Pattern.quote(attestationObjectValue), modifiedAttestationObjectB64_URLEncoded);

						request = requestResponse.request().withBody(requestBody);
					}
				} else if ( requestResponse.url().equalsIgnoreCase(settingForm.authenticationURL)) {
					Matcher matcherClientDataJSON = settingForm.authenticationCompiledRegexClientDataJSON.matcher(requestBody);
					Matcher matcherAuthenticatorData = settingForm.authenticationCompiledRegexAuthenticatorData.matcher(requestBody);
					Matcher matcherSignature = settingForm.authenticationCompiledRegexSignature.matcher(requestBody);

					if (matcherClientDataJSON.find() && matcherAuthenticatorData.find() && matcherSignature.find()) {
						String clientDataJSONValue = matcherClientDataJSON.group(1);
						String authenticatorDataValue = matcherAuthenticatorData.group(1);
						String signatureValue = matcherSignature.group(1);

						// encode clientDataJSON
						@SuppressWarnings("unchecked") Map<String, Object> clientDataJSON = (Map<String, Object>) textEditorContent.get("clientDataJSON");
						String modifiedClientDataJSONB64URL = util.encodeClientDataJSON(clientDataJSON);

						// encode authenticatorData
						@SuppressWarnings("unchecked") Map<String, Object> authenticatorDataJson = (Map<String, Object>) textEditorContent.get("authenticatorData");
						AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = util.encodeAuthenticatorData(authenticatorDataJson);
						byte[] authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData);
						String modifiedAuthenticatorDataB64URL = base64Utils.encodeToString(ByteArray.byteArray(authenticatorDataBytes), Base64EncodingOptions.URL);

						// sign
						byte[] clientDataJSONBytes = base64Utils.decode(modifiedClientDataJSONB64URL, Base64DecodingOptions.URL).getBytes();
						byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSONBytes);
						byte[] data = ByteBuffer.allocate(authenticatorDataBytes.length + clientDataHash.length).put(authenticatorDataBytes).put(clientDataHash).array();
						String modifiedSignatureB64URL = util.calculateSignature(settingForm.coseKey, data);

						// check Base64Url
						String modifiedClientDataJSONB64 = settingForm.isAuthenClientDataJsonBase64URL ? modifiedClientDataJSONB64URL : Util.base64UrlToBase64(modifiedClientDataJSONB64URL);
						String modifiedAuthenticatorDataB64 = settingForm.isAuthenAuthenticatorDataBase64URL ? modifiedAuthenticatorDataB64URL : Util.base64UrlToBase64(modifiedAuthenticatorDataB64URL);
						String modifiedSignatureB64 = settingForm.isAuthenSignatureBase64URL ? modifiedSignatureB64URL : Util.base64UrlToBase64(modifiedSignatureB64URL);

						// check URL encoded
						String modifiedClientDataJSONB64_URLEncoded = settingForm.isAuthenClientDataJsonURLEncoded ? urlUtils.encode(modifiedClientDataJSONB64) : modifiedClientDataJSONB64;
						String modifiedAuthenticatorDataB64_URLEncoded = settingForm.isAuthenAuthenticatorDataURLEncoded ? urlUtils.encode(modifiedAuthenticatorDataB64) : modifiedAuthenticatorDataB64;
						String modifiedSignatureB64_URLEncoded = settingForm.isAuthenSignatureURLEncoded ? urlUtils.encode(modifiedSignatureB64) : modifiedSignatureB64;

						requestBody = requestBody.replaceAll(Pattern.quote(clientDataJSONValue), modifiedClientDataJSONB64_URLEncoded);
						requestBody = requestBody.replaceAll(Pattern.quote(authenticatorDataValue), modifiedAuthenticatorDataB64_URLEncoded);
						requestBody = requestBody.replaceAll(Pattern.quote(signatureValue), modifiedSignatureB64_URLEncoded);

						request = requestResponse.request().withBody(requestBody);
					}
				}
			} else {
				request = requestResponse.request();
			}
		} catch (Exception e) {
			api.logging().logToOutput("Error getRequest: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}

		return request;
	}

	@Override
	public void setRequestResponse(HttpRequestResponse requestResponse)
	{
		try {
			this.requestResponse = requestResponse;
			String requestBody = requestResponse.request().bodyToString();
			this.requestEditor.setContents(ByteArray.byteArray());

			if (requestResponse.url().equalsIgnoreCase(settingForm.registrationURL)) {
				Matcher matcherClientDataJSON = settingForm.registrationCompiledRegexClientDataJSON.matcher(requestBody);
				Matcher matcherAttestationObject = settingForm.registrationCompiledRegexAttestationObject.matcher(requestBody);

				if (matcherClientDataJSON.find() && matcherAttestationObject.find()) {
					String clientDataJSONValue = matcherClientDataJSON.group(1);
					String attestationObjectValue = matcherAttestationObject.group(1);

					// check clientDataJSONValue URL encoded
					String clientDataJSON_URLDecoded = settingForm.isRegisterClientDataJsonURLEncoded ? urlUtils.decode(clientDataJSONValue) : clientDataJSONValue;

					// check attestationObjectValue URL encoded
					String attestationObject_URLDecoded = settingForm.isRegisterAttestationObjectURLEncoded ? urlUtils.decode(attestationObjectValue) : attestationObjectValue;

					Map<String, Object> output = new HashMap<>();
					output.put("clientDataJSON", util.decodeClientDataJSON(Util.base64ToBase64Url(clientDataJSON_URLDecoded)));
					output.put("attestationObject", util.decodeAttestationObject(Util.base64ToBase64Url(attestationObject_URLDecoded)));
					String outputJsonString = gsonPrettyPrinting.toJson(output);

					this.requestEditor.setContents(byteArray(outputJsonString));
				}
			} else if (requestResponse.url().equalsIgnoreCase(settingForm.authenticationURL)) {
				Matcher matcherClientDataJSON = settingForm.authenticationCompiledRegexClientDataJSON.matcher(requestBody);
				Matcher matcherAuthenticatorData = settingForm.authenticationCompiledRegexAuthenticatorData.matcher(requestBody);

				if (matcherClientDataJSON.find() && matcherAuthenticatorData.find()) {
					String clientDataJSONValue = matcherClientDataJSON.group(1);
					String authenticatorDataValue = matcherAuthenticatorData.group(1);

					// check URL encoded
					String clientDataJSON_URLDecoded = settingForm.isAuthenClientDataJsonURLEncoded ? urlUtils.decode(clientDataJSONValue) : clientDataJSONValue;
					String authenticatorData_URLDecoded = settingForm.isAuthenAuthenticatorDataURLEncoded ? urlUtils.decode(authenticatorDataValue) : authenticatorDataValue;

					Map<String, Object> output = new HashMap<>();
					output.put("clientDataJSON", util.decodeClientDataJSON(Util.base64ToBase64Url(clientDataJSON_URLDecoded)));

					byte[] authenticatorDataBytes = base64Utils.decode(Util.base64ToBase64Url(authenticatorData_URLDecoded), Base64DecodingOptions.URL).getBytes();

					AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataConverter.convert(authenticatorDataBytes);
					Map<String, Object> authenticatorDataJson = util.decodeAuthenticatorData(authenticatorData);
					output.put("authenticatorData", authenticatorDataJson);
					String outputJsonString = gsonPrettyPrinting.toJson(output);

					this.requestEditor.setContents(byteArray(outputJsonString));
				}
			}
		} catch (Exception e) {
			api.logging().logToOutput("Error setRequestResponse: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
	}

	@Override
	public boolean isEnabledFor(HttpRequestResponse requestResponse)
	{
		try {
			HttpRequest request = requestResponse.request();
			if (request != null) {
				String requestBody = request.bodyToString();
				String url;
				try {
					url = requestResponse.url();
				} catch (Exception e) {
					url = "";
				}
				if (url.equalsIgnoreCase(settingForm.registrationURL)) {
					Matcher matcherClientDataJSON = settingForm.registrationCompiledRegexClientDataJSON.matcher(requestBody);
					Matcher matcherAttestationObject = settingForm.registrationCompiledRegexAttestationObject.matcher(requestBody);

					return matcherClientDataJSON.find() && matcherAttestationObject.find();
				} else if (url.equalsIgnoreCase(settingForm.authenticationURL)) {
					Matcher matcherClientDataJSON = settingForm.authenticationCompiledRegexClientDataJSON.matcher(requestBody);
					Matcher matcherAuthenticatorData = settingForm.authenticationCompiledRegexAuthenticatorData.matcher(requestBody);
					Matcher matcherSignature = settingForm.authenticationCompiledRegexSignature.matcher(requestBody);

					return matcherClientDataJSON.find() && matcherAuthenticatorData.find() && matcherSignature.find();
				}
			}
		} catch (Exception e) {
			api.logging().logToOutput("Error isEnabledFor: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return false;
	}

	@Override
	public String caption()
	{
		return "Passkey Raider";
	}

	@Override
	public Component uiComponent()
	{
		return requestEditor.uiComponent();
	}

	@Override
	public Selection selectedData()
	{
		return requestEditor.selection().isPresent() ? requestEditor.selection().get() : null;
	}

	@Override
	public boolean isModified()
	{
		return requestEditor.isModified();
	}
}