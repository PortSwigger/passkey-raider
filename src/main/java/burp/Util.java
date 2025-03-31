package burp;


import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.utilities.Base64DecodingOptions;
import burp.api.montoya.utilities.Base64EncodingOptions;
import burp.api.montoya.utilities.Base64Utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.gson.ToNumberPolicy;
import com.webauthn4j.converter.jackson.deserializer.cbor.TPMSAttestDeserializer;
import com.webauthn4j.converter.jackson.deserializer.cbor.TPMTPublicDeserializer;
import com.webauthn4j.converter.jackson.serializer.cbor.TPMSAttestSerializer;
import com.webauthn4j.converter.jackson.serializer.cbor.TPMTPublicSerializer;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.attestation.statement.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.lang.reflect.Type;

public class Util {
	private final MontoyaApi api;
	private final Base64Utils base64Utils;
	private final Gson gsonPrettyPrinting;
	private final Gson gson;

	private final AttestationObjectConverter attestationObjectConverter;

	public static final byte BIT_UP = 0;
	public static final byte BIT_UV = 2;
	public static final byte BIT_BE = 3;
	public static final byte BIT_BS = 4;
	public static final byte BIT_AT = 6;
	public static final byte BIT_ED = 7;

	Util(MontoyaApi api) {
		this.api = api;
		base64Utils = api.utilities().base64Utils();
		ObjectConverter objectConverter = new ObjectConverter();
		attestationObjectConverter = new AttestationObjectConverter(objectConverter);
		gsonPrettyPrinting = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();
		gson = new GsonBuilder().disableHtmlEscaping().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();
	}

	public static KeyPair createEdDSAKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
		return keyPairGenerator.generateKeyPair();
	}

	public void logPrettyJson(String text, Map<String, Object> jsonObject) {
		try {
			api.logging().logToOutput("\n" + text + gsonPrettyPrinting.toJson(jsonObject));
		} catch (Exception e) {
			api.logging().logToOutput("Error logPrettyJson: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
	}

	public static byte[] hexStringToByteArray(String hex) {
		if (hex == null) {
			return null;
		}
		if (hex.length() % 2 != 0) {
			throw new IllegalArgumentException("Invalid hex string");
		}
		int length = hex.length();
		byte[] bytes = new byte[length / 2];
		for (int i = 0; i < length; i += 2) {
			bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
					+ Character.digit(hex.charAt(i + 1), 16));
		}
		return bytes;
	}

	public static String base64ToBase64Url(String base64) {
		return base64.replace('+', '-')
				.replace('/', '_')
				.replace("=", "");
	}

	public static String base64UrlToBase64(String base64Url) {
		String base64 = base64Url.replace('-', '+')
				.replace('_', '/');
		int paddingLength = (4 - base64.length() % 4) % 4;
		return base64 + "=".repeat(paddingLength);
	}

	public Map<String, Object> COSEKeyObjectToJson(COSEKey coseKey) {
		Map<String, Object> coseKeyJson = new HashMap<>();
		try {
			coseKeyJson.put("keyId", coseKey.getKeyId());
			coseKeyJson.put("algorithm", Objects.requireNonNull(coseKey.getAlgorithm()).toString());
			coseKeyJson.put("keyOps", coseKey.getKeyOps());

			// https://www.iana.org/assignments/cose/cose.xhtml#key-type
			if (coseKey instanceof EdDSACOSEKey) {
				coseKeyJson.put("keyType", "OKP");
				coseKeyJson.put("curve", ((EdDSACOSEKey) coseKey).getCurve());
				coseKeyJson.put("x", ArrayUtil.toHexString(((EdDSACOSEKey) coseKey).getX()));
				coseKeyJson.put("d", ArrayUtil.toHexString(((EdDSACOSEKey) coseKey).getD()));
			} else if (coseKey instanceof EC2COSEKey) {
				coseKeyJson.put("keyType", "EC2");
				coseKeyJson.put("curve", ((EC2COSEKey) coseKey).getCurve());
				coseKeyJson.put("x", ArrayUtil.toHexString(((EC2COSEKey) coseKey).getX()));
				coseKeyJson.put("y", ArrayUtil.toHexString(((EC2COSEKey) coseKey).getY()));
				coseKeyJson.put("d", ArrayUtil.toHexString(((EC2COSEKey) coseKey).getD()));
			} else if (coseKey instanceof RSACOSEKey) {
				coseKeyJson.put("keyType", "RSA");
				coseKeyJson.put("n", ArrayUtil.toHexString(((RSACOSEKey) coseKey).getN()));
				coseKeyJson.put("e", ArrayUtil.toHexString(((RSACOSEKey) coseKey).getE()));
				coseKeyJson.put("d", ArrayUtil.toHexString(((RSACOSEKey) coseKey).getD()));
				coseKeyJson.put("p", ArrayUtil.toHexString(((RSACOSEKey) coseKey).getP()));
				coseKeyJson.put("q", ArrayUtil.toHexString(((RSACOSEKey) coseKey).getQ()));
				coseKeyJson.put("dP", ArrayUtil.toHexString(((RSACOSEKey) coseKey).getDP()));
				coseKeyJson.put("dQ", ArrayUtil.toHexString(((RSACOSEKey) coseKey).getDQ()));
				coseKeyJson.put("qInv", ArrayUtil.toHexString(((RSACOSEKey) coseKey).getQInv()));
			}
		} catch (Exception e) {
			api.logging().logToOutput("Error COSEKeyObjectToJson: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return coseKeyJson;
	}

	public COSEKey COSEKeyJsonToObject(Map<String, Object> coseKeyJson) {
		COSEKey coseKey = null;
		Curve curve = null;
		byte[] x = new byte[0];
		byte[] d;
		try {
			byte[] keyId = hexStringToByteArray((String) coseKeyJson.get("keyId"));
			String algorithmString = (String) coseKeyJson.get("algorithm");

			// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
			COSEAlgorithmIdentifier algorithm = getCoseAlgorithmIdentifier(algorithmString);

			@SuppressWarnings("unchecked") List<COSEKeyOperation> keyOps = (List<COSEKeyOperation>) coseKeyJson.get("keyOps");

			// https://www.iana.org/assignments/cose/cose.xhtml#key-type
			if (Objects.equals(coseKeyJson.get("keyType"), "RSA")) {
				byte[] n = hexStringToByteArray((String) coseKeyJson.get("n"));
				byte[] e = hexStringToByteArray((String) coseKeyJson.get("e"));
				d = hexStringToByteArray((String) coseKeyJson.get("d"));
				byte[] p = hexStringToByteArray((String) coseKeyJson.get("p"));
				byte[] q = hexStringToByteArray((String) coseKeyJson.get("q"));
				byte[] dP = hexStringToByteArray((String) coseKeyJson.get("dP"));
				byte[] dQ = hexStringToByteArray((String) coseKeyJson.get("dQ"));
				byte[] qInv = hexStringToByteArray((String) coseKeyJson.get("qInv"));
				coseKey = new RSACOSEKey(keyId, algorithm, keyOps, n, e, d, p, q, dP, dQ, qInv);
			} else {
				String curveString = (String) coseKeyJson.get("curve");
				if (Objects.equals(curveString, "SECP256R1")) {
					curve = Curve.SECP256R1;
				} else if (Objects.equals(curveString, "SECP384R1")) {
					curve = Curve.SECP384R1;
				} else if (Objects.equals(curveString, "SECP521R1")) {
					curve = Curve.SECP521R1;
				} else if (Objects.equals(curveString, "ED25519")) {
					curve = Curve.ED25519;
				}
				x = hexStringToByteArray((String) coseKeyJson.get("x"));
				d = hexStringToByteArray((String) coseKeyJson.get("d"));
			}
			if (Objects.equals(coseKeyJson.get("keyType"), "EC2")) {
				byte[] y = hexStringToByteArray((String) coseKeyJson.get("y"));
				coseKey = new EC2COSEKey(keyId, algorithm, keyOps, curve, x, y, d);
			} else if (Objects.equals(coseKeyJson.get("keyType"), "OKP")) {
				coseKey = new EdDSACOSEKey(keyId, algorithm, keyOps, curve, x, d);
			}
		} catch (Exception e) {
			api.logging().logToOutput("Error COSEKeyJsonToObject: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return coseKey;
	}

	public String calculateSignature(COSEKey coseKey, byte[] data) {
		try {
			Signature signature = null;
			if (Objects.equals(coseKey.getAlgorithm(), COSEAlgorithmIdentifier.RS256)) {
				signature = Signature.getInstance("SHA256withRSA");
			} else if (Objects.equals(coseKey.getAlgorithm(), COSEAlgorithmIdentifier.ES256)) {
				signature = Signature.getInstance("SHA256withECDSA");
			} else if (Objects.equals(coseKey.getAlgorithm(), COSEAlgorithmIdentifier.RS1)) {
				signature = Signature.getInstance("SHA1withRSA");
			} else if (Objects.equals(coseKey.getAlgorithm(), COSEAlgorithmIdentifier.EdDSA)) {
				signature = Signature.getInstance("ed25519");
			} else if (Objects.equals(coseKey.getAlgorithm(), COSEAlgorithmIdentifier.RS384)) {
				signature = Signature.getInstance("SHA384withRSA");
			} else if (Objects.equals(coseKey.getAlgorithm(), COSEAlgorithmIdentifier.RS512)) {
				signature = Signature.getInstance("SHA512withRSA");
			} else if (Objects.equals(coseKey.getAlgorithm(), COSEAlgorithmIdentifier.ES384)) {
				signature = Signature.getInstance("SHA384withECDSA");
			} else if (Objects.equals(coseKey.getAlgorithm(), COSEAlgorithmIdentifier.ES512)) {
				signature = Signature.getInstance("SHA512withECDSA");
			}
			Objects.requireNonNull(signature).initSign(coseKey.getPrivateKey());
			signature.update(data);

			return base64Utils.encodeToString(ByteArray.byteArray(signature.sign()), Base64EncodingOptions.URL);
		} catch (Exception e) {
			api.logging().logToOutput("Signature calculation error: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
			return "";
		}
	}

	public <T extends ExtensionAuthenticatorOutput> Map<String, Object> decodeAuthenticatorData(AuthenticatorData<T> authenticatorData) {
		Map<String, Object> authenticatorDataJson = new HashMap<>();
		try {
			String rpIdHash = ArrayUtil.toHexString(authenticatorData.getRpIdHash());
			Map<String, Object> flagsJson = new HashMap<>();
			flagsJson.put("userPresent", authenticatorData.isFlagUP());
			flagsJson.put("userVerified", authenticatorData.isFlagUV());
			flagsJson.put("attestedCredentialData", authenticatorData.isFlagAT());
			flagsJson.put("extensionDataIncluded", authenticatorData.isFlagED());
			long signCount = ((Number) authenticatorData.getSignCount()).longValue();

			AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();
			Map<String, Object> attestedCredentialDataJson = new HashMap<>();
			if (attestedCredentialData != null) {
				AAGUID aaguid = attestedCredentialData.getAaguid();

				String credentialId = ArrayUtil.toHexString(attestedCredentialData.getCredentialId());

				COSEKey coseKey = attestedCredentialData.getCOSEKey();
				Map<String, Object> coseKeyJson = COSEKeyObjectToJson(coseKey);

				attestedCredentialDataJson.put("aaguid", aaguid.toString());
				attestedCredentialDataJson.put("credentialId", credentialId);
				attestedCredentialDataJson.put("coseKey", coseKeyJson);
			}

			AuthenticationExtensionsAuthenticatorOutputs<T> extensions = authenticatorData.getExtensions();
			Map<String, Object> extensionsJson = new HashMap<>();
			if (extensions != null) {
				UvmEntries uvm = extensions.getUvm();
				CredentialProtectionPolicy credProtect = extensions.getCredProtect();
				Object HMACSecret = extensions.getHMACSecret();
				extensionsJson.put("uvm", uvm);
				extensionsJson.put("credProtect", credProtect);
				extensionsJson.put("HMACSecret", HMACSecret);
			}

			// https://www.w3.org/TR/webauthn-1/#sec-authenticator-data
			// https://www.w3.org/TR/webauthn-1/#fig-authData
			authenticatorDataJson.put("rpIdHash", rpIdHash);
			authenticatorDataJson.put("flags", flagsJson);
			authenticatorDataJson.put("signCount", signCount);
			authenticatorDataJson.put("attestedCredentialData", attestedCredentialDataJson);
			authenticatorDataJson.put("extensions", extensionsJson);
		} catch (Exception e) {
			api.logging().logToOutput("Error decodeAuthenticatorData: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return authenticatorDataJson;
	}

	public Map<String, Object> decodeAttestationObject(String attestationObjectB64) {
		try {
			AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectB64);
			if (attestationObject != null) {
				// ----------------------- authenticatorData
				AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();
				Map<String, Object> authenticatorDataJson = decodeAuthenticatorData(authenticatorData);

				// ----------------------- attestationStatement
				AttestationStatement attestationStatement = attestationObject.getAttestationStatement();
				String attestationStatementFormat = attestationStatement.getFormat();
				Map<String, Object> attestationStatementJson = new HashMap<>();
				attestationStatementJson.put("format", attestationStatementFormat);

				AttestationCertificatePath x5c = null;
				if (attestationStatement instanceof AndroidKeyAttestationStatement) {
					attestationStatementJson.put("alg", ((AndroidKeyAttestationStatement) attestationStatement).getAlg().toString());
					attestationStatementJson.put("sig", ArrayUtil.toHexString(((AndroidKeyAttestationStatement) attestationStatement).getSig()));
					x5c = ((AndroidKeyAttestationStatement) attestationStatement).getX5c();
					attestationStatementJson.put("x5cString", ((AndroidKeyAttestationStatement) attestationStatement).getX5c().toString());
				} else if (attestationStatement instanceof AndroidSafetyNetAttestationStatement) {
					x5c = ((AndroidSafetyNetAttestationStatement) attestationStatement).getX5c();
					attestationStatementJson.put("x5cString", Objects.requireNonNull(((AndroidSafetyNetAttestationStatement) attestationStatement).getX5c()).toString());
					attestationStatementJson.put("ver", ((AndroidSafetyNetAttestationStatement) attestationStatement).getVer());

					Map<String, Object> responseJson = new HashMap<>();
					Response response = ((AndroidSafetyNetAttestationStatement) attestationStatement).getResponse().getPayload();
					responseJson.put("nonce", response.getNonce());
					responseJson.put("timestampMs", response.getTimestampMs());
					responseJson.put("apkPackageName", response.getApkPackageName());
					responseJson.put("apkCertificateDigestSha256", response.getApkCertificateDigestSha256());
					responseJson.put("apkDigestSha256", response.getApkDigestSha256());
					responseJson.put("ctsProfileMatch", response.getCtsProfileMatch());
					responseJson.put("basicIntegrity", response.getBasicIntegrity());
					responseJson.put("advice", response.getAdvice());
					responseJson.put("error", response.getError());

					attestationStatementJson.put("response", responseJson);
				} else if (attestationStatement instanceof AppleAnonymousAttestationStatement) {
					x5c = ((AppleAnonymousAttestationStatement) attestationStatement).getX5c();
					attestationStatementJson.put("x5cString", ((AppleAnonymousAttestationStatement) attestationStatement).getX5c().toString());
				} else if (attestationStatement instanceof FIDOU2FAttestationStatement) {
					x5c = ((FIDOU2FAttestationStatement) attestationStatement).getX5c();
					attestationStatementJson.put("sig", ArrayUtil.toHexString(((FIDOU2FAttestationStatement) attestationStatement).getSig()));
					attestationStatementJson.put("x5cString", ((FIDOU2FAttestationStatement) attestationStatement).getX5c().toString());
				} else if (attestationStatement instanceof PackedAttestationStatement) {
					x5c = ((PackedAttestationStatement) attestationStatement).getX5c();
					attestationStatementJson.put("alg", ((PackedAttestationStatement) attestationStatement).getAlg().toString());
					attestationStatementJson.put("sig", ArrayUtil.toHexString(((PackedAttestationStatement) attestationStatement).getSig()));
					attestationStatementJson.put("x5cString", Objects.requireNonNull(((PackedAttestationStatement) attestationStatement).getX5c()).toString());
				} else if (attestationStatement instanceof TPMAttestationStatement) {
					x5c = ((TPMAttestationStatement) attestationStatement).getX5c();
					attestationStatementJson.put("ver", ((TPMAttestationStatement) attestationStatement).getVer());
					attestationStatementJson.put("alg", ((TPMAttestationStatement) attestationStatement).getAlg().toString());
					attestationStatementJson.put("x5cString", Objects.requireNonNull(((TPMAttestationStatement) attestationStatement).getX5c()).toString());
					attestationStatementJson.put("sig", ArrayUtil.toHexString(((TPMAttestationStatement) attestationStatement).getSig()));

					ObjectMapper objectMapper = new ObjectMapper();
					SimpleModule module = new SimpleModule();
					module.addSerializer(TPMSAttest.class, new TPMSAttestSerializer());
					module.addSerializer(TPMTPublic.class, new TPMTPublicSerializer());
					objectMapper.registerModule(module);

					// ----- certInfo
					TPMSAttest certInfo = ((TPMAttestationStatement) attestationStatement).getCertInfo();
					String serializedCertInfo = objectMapper.writeValueAsString(certInfo);

					attestationStatementJson.put("certInfo", serializedCertInfo);

					// ----- pubArea
					TPMTPublic pubArea = ((TPMAttestationStatement) attestationStatement).getPubArea();
					String serializedPubArea = objectMapper.writeValueAsString(pubArea);

					attestationStatementJson.put("pubArea", serializedPubArea);
				}
				if (!(attestationStatement instanceof NoneAttestationStatement)) {
					List<String> certificates = new ArrayList<>();
					int x5c_size = Objects.requireNonNull(x5c).size();
					for (int i = 0; i < x5c_size; i++) {
						certificates.add(ArrayUtil.toHexString(x5c.get(i).getEncoded()));
					}
					attestationStatementJson.put("x5c", certificates);
				}

				Map<String, Object> attestationObjectJson = new HashMap<>();
				attestationObjectJson.put("authenticatorData", authenticatorDataJson);
				attestationObjectJson.put("attestationStatement", attestationStatementJson);
				attestationObjectJson.put("fmt", attestationObject.getFormat());

				return attestationObjectJson;
			}
		} catch (Exception e) {
			api.logging().logToOutput("Error decoding attestation object: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return new HashMap<>();
	}

	public AuthenticatorData encodeAuthenticatorData(Map<String, Object> authenticatorDataJson) {
		try {
			String rpIdHashString = (String) authenticatorDataJson.get("rpIdHash");
			byte[] rpIdHash = hexStringToByteArray(rpIdHashString);

			@SuppressWarnings("unchecked") Map<String, Object> flagsJson = (Map<String, Object>) authenticatorDataJson.get("flags");

			byte flags = 0;
			if ((boolean) flagsJson.getOrDefault("userPresent", false)) {
				flags = (byte) (flags | (1 << BIT_UP));
			}
			if ((boolean) flagsJson.getOrDefault("userVerified", false)) {
				flags = (byte) (flags | (1 << BIT_UV));
			}
			if ((boolean) flagsJson.getOrDefault("attestedCredentialData", false)) {
				flags = (byte) (flags | (1 << BIT_AT));
			}
			if ((boolean) flagsJson.getOrDefault("extensionDataIncluded", false)) {
				flags = (byte) (flags | (1 << BIT_ED));
			}
			long signCount = ((Number) authenticatorDataJson.get("signCount")).longValue();

			// ----------------------- attestedCredentialData
			@SuppressWarnings("unchecked") Map<String, Object> attestedCredentialDataJson = (Map<String, Object>) authenticatorDataJson.get("attestedCredentialData");
			AttestedCredentialData attestedCredentialData = null;
			if (attestedCredentialDataJson != null && !attestedCredentialDataJson.isEmpty()) {
				AAGUID aaguid = new AAGUID((String) attestedCredentialDataJson.get("aaguid"));
				byte[] credentialId = hexStringToByteArray((String) attestedCredentialDataJson.get("credentialId"));

				@SuppressWarnings("unchecked") Map<String, Object> coseKeyJson = (Map<String, Object>) attestedCredentialDataJson.get("coseKey");
				COSEKey coseKey = COSEKeyJsonToObject(coseKeyJson);

				attestedCredentialData = new AttestedCredentialData(aaguid, credentialId, coseKey);
			}

			// ----------------------- extensions
			@SuppressWarnings("unchecked") Map<String, Object> extensionsJson = (Map<String, Object>) authenticatorDataJson.get("extensions");
			AuthenticationExtensionsAuthenticatorOutputs extensions = null;
			if (extensionsJson != null && !extensionsJson.isEmpty()) {
				AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
				UvmEntries uvm = (UvmEntries) extensionsJson.get("uvm");
				CredentialProtectionPolicy credProtect = (CredentialProtectionPolicy) extensionsJson.get("credProtect");
				Boolean HMACSecret = (Boolean) extensionsJson.get("HMACSecret");
				builder.setUvm(uvm);
				builder.setCredProtect(credProtect);
				builder.setHMACCreateSecret(HMACSecret);
				extensions = builder.build();
			}
			return new AuthenticatorData(rpIdHash, flags, signCount, attestedCredentialData, extensions);
		} catch (Exception e) {
			api.logging().logToOutput("Error encodeAuthenticatorData: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return null;
	}

	public String encodeAttestationObject(Map<String, Object> attestationObjectJson) {
		try {
			// ----------------------- authenticatorData
			@SuppressWarnings("unchecked") Map<String, Object> authenticatorDataJson = (Map<String, Object>) attestationObjectJson.get("authenticatorData");
			AuthenticatorData authenticatorData = encodeAuthenticatorData(authenticatorDataJson);

			// ----------------------- attestationStatement
			@SuppressWarnings("unchecked") Map<String, Object> attestationStatementJson = (Map<String, Object>) attestationObjectJson.get("attestationStatement");

			String format = (String) attestationStatementJson.get("format");
			String algString = (String) attestationStatementJson.get("alg");
			COSEAlgorithmIdentifier alg = getCoseAlgorithmIdentifier(algString);

			AttestationCertificatePath x5c = null;
			if (!Objects.equals(format, "none")) {
				@SuppressWarnings("unchecked") List<String> certificateStrings = (List<String>) attestationStatementJson.get("x5c");
				List<X509Certificate> certificates = new ArrayList<>();
				for (String certificateString : certificateStrings) {
					byte[] encodedCertificate = hexStringToByteArray(certificateString);
					CertificateFactory factory = CertificateFactory.getInstance("X.509");
					certificates.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encodedCertificate)));
				}
				x5c = new AttestationCertificatePath(certificates);
			}

			AttestationStatement attestationStatement = null;
			if (Objects.equals(format, "none")) {
				attestationStatement = new NoneAttestationStatement();
			} else if (Objects.equals(format, "android-key")) {
				byte[] sig = hexStringToByteArray((String) attestationStatementJson.get("sig"));
				attestationStatement = new AndroidKeyAttestationStatement(alg, sig, Objects.requireNonNull(x5c));

			} else if (Objects.equals(format, "android-safetynet")) {
				String ver = (String) attestationStatementJson.get("ver");
				@SuppressWarnings("unchecked") Map<String, Object> responseJson = (Map<String, Object>) attestationStatementJson.get("response");

				String nonce = (String) responseJson.get("nonce");
				Long timestampMs = (Long) responseJson.get("timestampMs");
				String apkPackageName = (String) responseJson.get("apkPackageName");
				String[] apkCertificateDigestSha256 = (String[]) responseJson.get("apkCertificateDigestSha256");
				String apkDigestSha256 = (String) responseJson.get("apkDigestSha256");
				Boolean ctsProfileMatch = (Boolean) responseJson.get("ctsProfileMatch");
				Boolean basicIntegrity = (Boolean) responseJson.get("basicIntegrity");
				String advice = (String) responseJson.get("advice");
				String error = (String) responseJson.get("error");

				Response responseObject = new Response(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, basicIntegrity, advice, error);
				JWS<Response> response = new JWSFactory().create(new JWSHeader(JWAIdentifier.ES256, Objects.requireNonNull(x5c).createCertPath()), responseObject, new byte[32]);

				attestationStatement = new AndroidSafetyNetAttestationStatement(ver, response);

			} else if (Objects.equals(format, "apple")) {
				attestationStatement = new AppleAnonymousAttestationStatement(Objects.requireNonNull(x5c));

			} else if (Objects.equals(format, "fido-u2f")) {
				byte[] sig = hexStringToByteArray((String) attestationStatementJson.get("sig"));
				attestationStatement = new FIDOU2FAttestationStatement(Objects.requireNonNull(x5c), sig);

			} else if (Objects.equals(format, "packed")) {
				byte[] sig = hexStringToByteArray((String) attestationStatementJson.get("sig"));
				attestationStatement = new PackedAttestationStatement(alg, sig, x5c);

			} else if (Objects.equals(format, "tpm")) {
				String ver = (String) attestationStatementJson.get("ver");
				byte[] sig = hexStringToByteArray((String) attestationStatementJson.get("sig"));

				ObjectMapper objectMapper = new ObjectMapper();
				SimpleModule module = new SimpleModule();
				module.addDeserializer(TPMSAttest.class, new TPMSAttestDeserializer());
				module.addDeserializer(TPMTPublic.class, new TPMTPublicDeserializer());
				objectMapper.registerModule(module);

				String serializedCertInfo = (String) attestationStatementJson.get("certInfo");
				TPMSAttest certInfo = objectMapper.readValue(serializedCertInfo, TPMSAttest.class);

				String serializedPubArea = (String) attestationStatementJson.get("pubArea");
				TPMTPublic pubArea = objectMapper.readValue(serializedPubArea, TPMTPublic.class);

				attestationStatement = new TPMAttestationStatement(ver, alg, x5c, sig, certInfo, pubArea);
			}

			@SuppressWarnings("unchecked") AttestationObject attestationObject = new AttestationObject((AuthenticatorData<RegistrationExtensionAuthenticatorOutput>) authenticatorData, Objects.requireNonNull(attestationStatement));

			byte[] bytes = attestationObjectConverter.convertToBytes(attestationObject);
			return base64Utils.encodeToString(ByteArray.byteArray(bytes), Base64EncodingOptions.URL);
		} catch (Exception e) {
			api.logging().logToOutput("Error encoding attestation object: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return "";
	}

	private static COSEAlgorithmIdentifier getCoseAlgorithmIdentifier(String algString) {
		COSEAlgorithmIdentifier alg = null;
		if (algString != null) {
			alg = switch (algString) {
				case "RS256" -> COSEAlgorithmIdentifier.RS256;
				case "ES256" -> COSEAlgorithmIdentifier.ES256;
				case "RS1" -> COSEAlgorithmIdentifier.RS1;
				case "EdDSA" -> COSEAlgorithmIdentifier.EdDSA;
				case "RS384" -> COSEAlgorithmIdentifier.RS384;
				case "RS512" -> COSEAlgorithmIdentifier.RS512;
				case "ES384" -> COSEAlgorithmIdentifier.ES384;
				case "ES512" -> COSEAlgorithmIdentifier.ES512;
				default -> null;
			};
		}
		return alg;
	}

	public Map<String, Object> decodeClientDataJSON(String clientDataJSONB64) {
		try {
			String clientDataJSONString = String.valueOf(base64Utils.decode(clientDataJSONB64, Base64DecodingOptions.URL));
			Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
			return gsonPrettyPrinting.fromJson(clientDataJSONString, mapType);
		} catch (Exception e) {
			api.logging().logToOutput("Error decoding ClientDataJSON: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return new HashMap<>();
	}

	public String encodeClientDataJSON(Map<String, Object> clientData) {
		try {
			String jsonString = gson.toJson(clientData);
			return base64Utils.encodeToString(ByteArray.byteArray(jsonString.getBytes()), Base64EncodingOptions.URL);
		} catch (Exception e) {
			api.logging().logToOutput("Error encoding ClientDataJSON: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return null;
	}
}
