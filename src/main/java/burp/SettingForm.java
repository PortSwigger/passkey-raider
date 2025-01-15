package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.RSAUtil;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.lang.reflect.Type;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class SettingForm {
	private JPanel mainPanel;
	private JPanel registrationPanel;
	private JTextField registrationUrlField;
	private JTextField registrationClientDataJSONField;
	private JTextField registrationAttestationObjectField;
	private JPanel authenticationPanel;
	private JTextField authenticationSignatureField;
	private JTextField authenticationAuthenticatorDataField;
	private JTextField authenticationClientDataJSONField;
	private JTextField authenticationUrlField;
	private JPanel coseKeyPanel;
	private JTextArea coseKeyField;
	private JPanel algorithmPanel;
	private JRadioButton RS256RadioButton;
	private JRadioButton ES256RadioButton;
	private JRadioButton edDSARadioButton;
	private JRadioButton RS384RadioButton;
	private JRadioButton RS1RadioButton;
	private JRadioButton RS512RadioButton;
	private JRadioButton ES384RadioButton;
	private JRadioButton ES512RadioButton;
	private JButton generateButton;
	private JButton saveButton;

	private final MontoyaApi api;
	private final Util util;
	Gson gsonPrettyPrinting;
	Type mapType;

	private final PersistedObject settingData;

	public String registrationURL = "";
	public String registrationRegexClientDataJSON = "\"clientDataJSON\":\"([^\"]+)";
	public String registrationRegexAttestationObject = "\"attestationObject\":\"([^\"]+)";

	public String authenticationURL = "";
	public String authenticationRegexClientDataJSON = "\"clientDataJSON\":\"([^\"]+)";
	public String authenticationRegexAuthenticatorData = "\"authenticatorData\":\"([^\"]+)";
	public String authenticationRegexSignature = "\"signature\":\"([^\"]+)";
	public String coseKeyJsonString;
	public COSEKey coseKey;
	Map<String, Object> coseKeyJson;
	String algorithm = "";

	SettingForm(MontoyaApi api) {
		this.api = api;
		this.util = new Util(api);
		mapType = new TypeToken<Map<String, Object>>() {
		}.getType();
		gsonPrettyPrinting = new GsonBuilder().setPrettyPrinting().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();

		settingData = api.persistence().extensionData();
		registrationURL = settingData.getString("registrationURL") != null ? settingData.getString("registrationURL") : registrationURL;
		registrationRegexClientDataJSON = settingData.getString("registrationClientDataJSON") != null ? settingData.getString("registrationClientDataJSON") : registrationRegexClientDataJSON;
		registrationRegexAttestationObject = settingData.getString("registrationAttestationObject") != null ? settingData.getString("registrationAttestationObject") : registrationRegexAttestationObject;
		authenticationURL = settingData.getString("authenticationURL") != null ? settingData.getString("authenticationURL") : authenticationURL;
		authenticationRegexClientDataJSON = settingData.getString("authenticationClientDataJSON") != null ? settingData.getString("authenticationClientDataJSON") : authenticationRegexClientDataJSON;
		authenticationRegexAuthenticatorData = settingData.getString("authenticationAuthenticatorData") != null ? settingData.getString("authenticationAuthenticatorData") : authenticationRegexAuthenticatorData;
		authenticationRegexSignature = settingData.getString("authenticationSignature") != null ? settingData.getString("authenticationSignature") : authenticationRegexSignature;

		coseKeyJsonString = settingData.getString("coseKeyJsonString") != null ? settingData.getString("coseKeyJsonString") : generateCOSEKey();

		coseKeyJson = gsonPrettyPrinting.fromJson(coseKeyJsonString, mapType);
		coseKey = util.COSEKeyJsonToObject(coseKeyJson);
		switch ((String) coseKeyJson.get("algorithm")) {
			case "ES256" -> ES256RadioButton.setSelected(true);
			case "RS1" -> RS1RadioButton.setSelected(true);
			case "EdDSA" -> edDSARadioButton.setSelected(true);
			case "RS384" -> RS384RadioButton.setSelected(true);
			case "RS512" -> RS512RadioButton.setSelected(true);
			case "ES384" -> ES384RadioButton.setSelected(true);
			case "ES512" -> ES512RadioButton.setSelected(true);
			default -> RS256RadioButton.setSelected(true);
		}

		printSetting(true);

		registrationUrlField.setText(registrationURL);
		registrationClientDataJSONField.setText(registrationRegexClientDataJSON);
		registrationAttestationObjectField.setText(registrationRegexAttestationObject);

		authenticationUrlField.setText(authenticationURL);
		authenticationClientDataJSONField.setText(authenticationRegexClientDataJSON);
		authenticationAuthenticatorDataField.setText(authenticationRegexAuthenticatorData);
		authenticationSignatureField.setText(authenticationRegexSignature);

		coseKeyField.setText(coseKeyJsonString);
		generateButton.addActionListener(e -> {
			coseKeyField.setText(generateCOSEKey());
		});

		saveButton.addActionListener(e -> {
			registrationURL = registrationUrlField.getText().trim();
			registrationRegexClientDataJSON = registrationClientDataJSONField.getText().trim();
			registrationRegexAttestationObject = registrationAttestationObjectField.getText().trim();
			authenticationURL = authenticationUrlField.getText().trim();
			authenticationRegexClientDataJSON = authenticationClientDataJSONField.getText().trim();
			authenticationRegexAuthenticatorData = authenticationAuthenticatorDataField.getText().trim();
			authenticationRegexSignature = authenticationSignatureField.getText().trim();
			coseKeyJsonString = coseKeyField.getText();
			coseKeyJson = gsonPrettyPrinting.fromJson(coseKeyJsonString, mapType);
			coseKey = util.COSEKeyJsonToObject(coseKeyJson);

			settingData.setString("registrationURL", registrationURL);
			settingData.setString("registrationClientDataJSON", registrationRegexClientDataJSON);
			settingData.setString("registrationAttestationObject", registrationRegexAttestationObject);

			settingData.setString("authenticationURL", authenticationURL);
			settingData.setString("authenticationClientDataJSON", authenticationRegexClientDataJSON);
			settingData.setString("authenticationAuthenticatorData", authenticationRegexAuthenticatorData);
			settingData.setString("authenticationSignature", authenticationRegexSignature);

			settingData.setString("coseKeyJsonString", coseKeyJsonString);

			printSetting(false);
		});
	}

	public JPanel getUI() {
		return this.mainPanel;
	}

	private String generateCOSEKey() {
		try {
			if (RS256RadioButton.isSelected()) {
				algorithm = "RS256";
			} else if (ES256RadioButton.isSelected()) {
				algorithm = "ES256";
			} else if (edDSARadioButton.isSelected()) {
				algorithm = "EdDSA";
			} else if (RS384RadioButton.isSelected()) {
				algorithm = "RS384";
			} else if (RS1RadioButton.isSelected()) {
				algorithm = "RS1";
			} else if (RS512RadioButton.isSelected()) {
				algorithm = "RS512";
			} else if (ES384RadioButton.isSelected()) {
				algorithm = "ES384";
			} else if (ES512RadioButton.isSelected()) {
				algorithm = "ES512";
			}
			coseKey = switch (algorithm) {
				case "RS256" -> RSACOSEKey.create(RSAUtil.createKeyPair(), COSEAlgorithmIdentifier.RS256);
				case "RS1" -> RSACOSEKey.create(RSAUtil.createKeyPair(), COSEAlgorithmIdentifier.RS1);
				case "RS384" -> RSACOSEKey.create(RSAUtil.createKeyPair(), COSEAlgorithmIdentifier.RS384);
				case "RS512" -> RSACOSEKey.create(RSAUtil.createKeyPair(), COSEAlgorithmIdentifier.RS512);
				case "ES256" -> EC2COSEKey.create(ECUtil.createKeyPair(), COSEAlgorithmIdentifier.ES256);
				case "ES384" -> EC2COSEKey.create(ECUtil.createKeyPair(), COSEAlgorithmIdentifier.ES384);
				case "ES512" -> EC2COSEKey.create(ECUtil.createKeyPair(), COSEAlgorithmIdentifier.ES512);
				case "EdDSA" -> EdDSACOSEKey.create(Util.createEdDSAKeyPair());
				default -> coseKey;
			};
			Map<String, Object> coseKeyJson = util.COSEKeyObjectToJson(coseKey);
			return gsonPrettyPrinting.toJson(coseKeyJson);
		} catch (Exception e) {
			api.logging().logToOutput("Error generateCOSEKey: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
		return "";
	}

	private void printSetting(boolean isLoad) {
		try {
			if (isLoad)
				api.logging().logToOutput("\n============= Load Setting =============");
			else
				api.logging().logToOutput("\n============= Save Setting =============");
			api.logging().logToOutput("Passkey Registration URL: " + registrationURL);
			api.logging().logToOutput("Regex to extract Registration's clientDataJSON: " + registrationRegexClientDataJSON);
			api.logging().logToOutput("Regex to extract Registration's attestationObject: " + registrationRegexAttestationObject);
			api.logging().logToOutput("Passkey Authentication URL: " + authenticationURL);
			api.logging().logToOutput("Regex to extract Authentication's clientDataJSON: " + authenticationRegexClientDataJSON);
			api.logging().logToOutput("Regex to extract Authentication's authenticatorData: " + authenticationRegexAuthenticatorData);
			api.logging().logToOutput("Regex to extract Authentication's signature: " + authenticationRegexSignature);
			api.logging().logToOutput("COSE Key: " + coseKeyJsonString);
		} catch (Exception e) {
			api.logging().logToOutput("Error printSetting: " + e.getMessage());
			for (StackTraceElement element : e.getStackTrace()) {
				api.logging().logToOutput("\tat " + element);
			}
		}
	}

	{
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
		$$$setupUI$$$();
	}

	/**
	 * Method generated by IntelliJ IDEA GUI Designer
	 * >>> IMPORTANT!! <<<
	 * DO NOT edit this method OR call it in your code!
	 *
	 * @noinspection ALL
	 */
	private void $$$setupUI$$$() {
		mainPanel = new JPanel();
		mainPanel.setLayout(new GridLayoutManager(4, 2, new Insets(10, 10, 10, 10), -1, -1));
		mainPanel.setMaximumSize(new Dimension(400, 2147483647));
		mainPanel.setMinimumSize(new Dimension(400, 503));
		mainPanel.setPreferredSize(new Dimension(400, 503));
		coseKeyPanel = new JPanel();
		coseKeyPanel.setLayout(new GridLayoutManager(3, 4, new Insets(10, 10, 10, 10), -1, -1));
		mainPanel.add(coseKeyPanel, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, new Dimension(800, -1), 0, false));
		coseKeyPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "COSE Key", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
		final JLabel label1 = new JLabel();
		label1.setText("Algorithm");
		coseKeyPanel.add(label1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		algorithmPanel = new JPanel();
		algorithmPanel.setLayout(new GridLayoutManager(1, 8, new Insets(0, 0, 0, 0), -1, -1));
		coseKeyPanel.add(algorithmPanel, new GridConstraints(1, 1, 1, 3, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
		algorithmPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
		ES256RadioButton = new JRadioButton();
		ES256RadioButton.setSelected(false);
		ES256RadioButton.setText("ES256");
		algorithmPanel.add(ES256RadioButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		edDSARadioButton = new JRadioButton();
		edDSARadioButton.setText("EdDSA");
		algorithmPanel.add(edDSARadioButton, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		RS384RadioButton = new JRadioButton();
		RS384RadioButton.setText("RS384");
		algorithmPanel.add(RS384RadioButton, new GridConstraints(0, 4, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		RS1RadioButton = new JRadioButton();
		RS1RadioButton.setText("RS1");
		algorithmPanel.add(RS1RadioButton, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		RS512RadioButton = new JRadioButton();
		RS512RadioButton.setText("RS512");
		algorithmPanel.add(RS512RadioButton, new GridConstraints(0, 5, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		ES384RadioButton = new JRadioButton();
		ES384RadioButton.setText("ES384");
		algorithmPanel.add(ES384RadioButton, new GridConstraints(0, 6, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		ES512RadioButton = new JRadioButton();
		ES512RadioButton.setText("ES512");
		algorithmPanel.add(ES512RadioButton, new GridConstraints(0, 7, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		RS256RadioButton = new JRadioButton();
		RS256RadioButton.setSelected(true);
		RS256RadioButton.setText("RS256");
		algorithmPanel.add(RS256RadioButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		generateButton = new JButton();
		generateButton.setText("Generate");
		coseKeyPanel.add(generateButton, new GridConstraints(2, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		final Spacer spacer1 = new Spacer();
		coseKeyPanel.add(spacer1, new GridConstraints(2, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
		final JLabel label2 = new JLabel();
		label2.setText("Generated COSE Key");
		coseKeyPanel.add(label2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		final JScrollPane scrollPane1 = new JScrollPane();
		coseKeyPanel.add(scrollPane1, new GridConstraints(0, 1, 1, 3, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
		coseKeyField = new JTextArea();
		coseKeyField.setLineWrap(true);
		coseKeyField.setRequestFocusEnabled(true);
		coseKeyField.setRows(10);
		coseKeyField.setText("");
		scrollPane1.setViewportView(coseKeyField);
		registrationPanel = new JPanel();
		registrationPanel.setLayout(new GridLayoutManager(3, 2, new Insets(10, 10, 10, 10), -1, -1));
		mainPanel.add(registrationPanel, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, new Dimension(800, -1), 0, false));
		registrationPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Passkey Registration", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
		final JLabel label3 = new JLabel();
		label3.setText("Passkey Registration URL:");
		registrationPanel.add(label3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		registrationUrlField = new JTextField();
		registrationPanel.add(registrationUrlField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
		final JLabel label4 = new JLabel();
		label4.setText("Regex to extract Registration's clientDataJSON:");
		registrationPanel.add(label4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		registrationClientDataJSONField = new JTextField();
		registrationPanel.add(registrationClientDataJSONField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
		final JLabel label5 = new JLabel();
		label5.setText("Regex to extract Registration's attestationObject:");
		registrationPanel.add(label5, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		registrationAttestationObjectField = new JTextField();
		registrationPanel.add(registrationAttestationObjectField, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
		authenticationPanel = new JPanel();
		authenticationPanel.setLayout(new GridLayoutManager(4, 2, new Insets(10, 10, 10, 10), -1, -1));
		mainPanel.add(authenticationPanel, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, new Dimension(800, -1), 0, false));
		authenticationPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Passkey Authentication", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
		final JLabel label6 = new JLabel();
		label6.setText("Passkey Authentication URL:");
		authenticationPanel.add(label6, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		authenticationUrlField = new JTextField();
		authenticationPanel.add(authenticationUrlField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
		final JLabel label7 = new JLabel();
		label7.setText("Regex to extract Authentication's clientDataJSON:");
		authenticationPanel.add(label7, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		authenticationClientDataJSONField = new JTextField();
		authenticationPanel.add(authenticationClientDataJSONField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
		final JLabel label8 = new JLabel();
		label8.setText("Regex to extract Authentication's authenticatorData:");
		authenticationPanel.add(label8, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		authenticationAuthenticatorDataField = new JTextField();
		authenticationPanel.add(authenticationAuthenticatorDataField, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
		final JLabel label9 = new JLabel();
		label9.setText("Regex to extract Authentication's signature:");
		authenticationPanel.add(label9, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		authenticationSignatureField = new JTextField();
		authenticationPanel.add(authenticationSignatureField, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
		final JPanel panel1 = new JPanel();
		panel1.setLayout(new GridLayoutManager(2, 2, new Insets(0, 0, 0, 0), -1, -1));
		mainPanel.add(panel1, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, new Dimension(800, -1), 0, false));
		saveButton = new JButton();
		saveButton.setText("Save");
		panel1.add(saveButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
		final Spacer spacer2 = new Spacer();
		panel1.add(spacer2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
		final Spacer spacer3 = new Spacer();
		panel1.add(spacer3, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
		ButtonGroup buttonGroup;
		buttonGroup = new ButtonGroup();
		buttonGroup.add(ES256RadioButton);
		buttonGroup.add(RS1RadioButton);
		buttonGroup.add(edDSARadioButton);
		buttonGroup.add(RS384RadioButton);
		buttonGroup.add(RS512RadioButton);
		buttonGroup.add(ES384RadioButton);
		buttonGroup.add(ES512RadioButton);
		buttonGroup.add(RS256RadioButton);
	}

	/**
	 * @noinspection ALL
	 */
	public JComponent $$$getRootComponent$$$() {
		return mainPanel;
	}

}
