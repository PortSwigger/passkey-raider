package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;

public class PasskeyEditorExtension implements BurpExtension
{
	@Override
	public void initialize(MontoyaApi api)
	{
		api.extension().setName("Passkey Raider");

		SettingForm settingForm = new SettingForm(api);

		SwingUtilities.invokeLater(() -> {
			api.userInterface().registerSuiteTab("Passkey Raider", settingForm.getUI());
		});

		api.userInterface().registerHttpRequestEditorProvider(new MyHttpRequestEditorProvider(settingForm, api));

		// Register proxy handlers with Burp.
		api.proxy().registerRequestHandler(new MyProxyHttpRequestHandler(settingForm, api));
		api.proxy().registerResponseHandler(new MyProxyHttpResponseHandler());
	}
}
