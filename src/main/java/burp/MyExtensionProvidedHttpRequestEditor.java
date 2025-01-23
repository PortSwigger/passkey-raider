package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.utilities.Base64EncodingOptions;
import burp.api.montoya.utilities.Base64Utils;

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
	private final Base64Utils base64Utils;
	private HttpRequestResponse requestResponse;
	private final SettingForm settingForm;
	private final MontoyaApi api;
	private final Gson gsonPrettyPrinting;
	private final Util util;

	private final AuthenticatorDataConverter authenticatorDataConverter;

	MyExtensionProvidedHttpRequestEditor(SettingForm settingForm, MontoyaApi api, EditorCreationContext creationContext)
	{
		this.settingForm = settingForm;
		this.api = api;
		this.util = new Util(api);
		ObjectConverter objectConverter = new ObjectConverter();
		authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);

		gsonPrettyPrinting = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();

		base64Utils = api.utilities().base64Utils();

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
					Pattern patternClientDataJSON = Pattern.compile(settingForm.registrationRegexClientDataJSON);
					Matcher matcherClientDataJSON = patternClientDataJSON.matcher(requestBody);

					Pattern patternAttestationObject = Pattern.compile(settingForm.registrationRegexAttestationObject);
					Matcher matcherAttestationObject = patternAttestationObject.matcher(requestBody);

					if (matcherClientDataJSON.find() && matcherAttestationObject.find()) {
						String clientDataJSONValue = matcherClientDataJSON.group(1);
						String attestationObjectValue = matcherAttestationObject.group(1);

						@SuppressWarnings("unchecked") Map<String, Object> clientDataJSON = (Map<String, Object>) textEditorContent.get("clientDataJSON");
						@SuppressWarnings("unchecked") Map<String, Object> attestationObject = (Map<String, Object>) textEditorContent.get("attestationObject");

						String modifiedClientDataJSONB64 = util.encodeClientDataJSON(clientDataJSON);
						String modifiedAttestationObjectB64 = util.encodeAttestationObject(attestationObject);

						requestBody = requestBody.replaceAll(clientDataJSONValue, modifiedClientDataJSONB64);
						requestBody = requestBody.replaceAll(attestationObjectValue, modifiedAttestationObjectB64);

						request = requestResponse.request().withBody(requestBody);
					}
				} else if ( requestResponse.url().equalsIgnoreCase(settingForm.authenticationURL)) {
					Pattern patternClientDataJSON = Pattern.compile(settingForm.authenticationRegexClientDataJSON);
					Matcher matcherClientDataJSON = patternClientDataJSON.matcher(requestBody);

					Pattern patternAuthenticatorData = Pattern.compile(settingForm.authenticationRegexAuthenticatorData);
					Matcher matcherAuthenticatorData = patternAuthenticatorData.matcher(requestBody);

					Pattern patternSignature = Pattern.compile(settingForm.authenticationRegexSignature);
					Matcher matcherSignature = patternSignature.matcher(requestBody);

					if (matcherClientDataJSON.find() && matcherAuthenticatorData.find() && matcherSignature.find()) {
						String clientDataJSONValue = matcherClientDataJSON.group(1);
						String authenticatorDataValue = matcherAuthenticatorData.group(1);
						String signatureValue = matcherSignature.group(1);

						// encode clientDataJSON
						@SuppressWarnings("unchecked") Map<String, Object> clientDataJSON = (Map<String, Object>) textEditorContent.get("clientDataJSON");
						String modifiedClientDataJSONB64 = util.encodeClientDataJSON(clientDataJSON);

						// encode authenticatorData
						@SuppressWarnings("unchecked") Map<String, Object> authenticatorDataJson = (Map<String, Object>) textEditorContent.get("authenticatorData");
						AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = util.encodeAuthenticatorData(authenticatorDataJson);
						byte[] authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData);
						String modifiedAuthenticatorDataB64 = Base64UrlUtil.encodeToString(authenticatorDataBytes);
						// sign
						byte[] clientDataJSONBytes = Base64UrlUtil.decode(modifiedClientDataJSONB64);
						byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSONBytes);
						byte[] data = ByteBuffer.allocate(authenticatorDataBytes.length + clientDataHash.length).put(authenticatorDataBytes).put(clientDataHash).array();
						String modifiedSignature = util.calculateSignature(settingForm.coseKey, data);

						requestBody = requestBody.replaceAll(clientDataJSONValue, modifiedClientDataJSONB64);
						requestBody = requestBody.replaceAll(authenticatorDataValue, modifiedAuthenticatorDataB64);
						requestBody = requestBody.replaceAll(signatureValue, modifiedSignature);

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

			if (requestResponse.url().equalsIgnoreCase(settingForm.registrationURL)) {
				Pattern patternClientDataJSON = Pattern.compile(settingForm.registrationRegexClientDataJSON);
				Matcher matcherClientDataJSON = patternClientDataJSON.matcher(requestBody);

				Pattern patternAttestationObject = Pattern.compile(settingForm.registrationRegexAttestationObject);
				Matcher matcherAttestationObject = patternAttestationObject.matcher(requestBody);

				if (matcherClientDataJSON.find() && matcherAttestationObject.find()) {
					String clientDataJSONValue = matcherClientDataJSON.group(1);
					String attestationObjectValue = matcherAttestationObject.group(1);

					Map<String, Object> output = new HashMap<>();
					output.put("clientDataJSON", util.decodeClientDataJSON(clientDataJSONValue));
					output.put("attestationObject", util.decodeAttestationObject(attestationObjectValue));
					String outputJsonString = gsonPrettyPrinting.toJson(output);

					this.requestEditor.setContents(byteArray(outputJsonString));
				}
			} else if ( requestResponse.url().equalsIgnoreCase(settingForm.authenticationURL)) {
				Pattern patternClientDataJSON = Pattern.compile(settingForm.authenticationRegexClientDataJSON);
				Matcher matcherClientDataJSON = patternClientDataJSON.matcher(requestBody);

				Pattern patternAuthenticatorData = Pattern.compile(settingForm.authenticationRegexAuthenticatorData);
				Matcher matcherAuthenticatorData = patternAuthenticatorData.matcher(requestBody);

				if (matcherClientDataJSON.find() && matcherAuthenticatorData.find()) {
					String clientDataJSONValue = matcherClientDataJSON.group(1);
					String authenticatorDataValue = matcherAuthenticatorData.group(1);

					Map<String, Object> output = new HashMap<>();
					output.put("clientDataJSON", util.decodeClientDataJSON(clientDataJSONValue));

					byte[] authenticatorDataBytes = Base64UrlUtil.decode(authenticatorDataValue);

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
					Pattern patternClientDataJSON = Pattern.compile(settingForm.registrationRegexClientDataJSON);
					Matcher matcherClientDataJSON = patternClientDataJSON.matcher(requestBody);

					Pattern patternAttestationObject = Pattern.compile(settingForm.registrationRegexAttestationObject);
					Matcher matcherAttestationObject = patternAttestationObject.matcher(requestBody);

					return matcherClientDataJSON.find() && matcherAttestationObject.find();
				} else if (url.equalsIgnoreCase(settingForm.authenticationURL)) {
					Pattern patternClientDataJSON = Pattern.compile(settingForm.authenticationRegexClientDataJSON);
					Matcher matcherClientDataJSON = patternClientDataJSON.matcher(requestBody);

					Pattern patternAuthenticatorData = Pattern.compile(settingForm.authenticationRegexAuthenticatorData);
					Matcher matcherAuthenticatorData = patternAuthenticatorData.matcher(requestBody);

					Pattern patternSignature = Pattern.compile(settingForm.authenticationRegexSignature);
					Matcher matcherSignature = patternSignature.matcher(requestBody);

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