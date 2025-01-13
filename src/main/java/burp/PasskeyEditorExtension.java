/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
import java.awt.*;

public class PasskeyEditorExtension implements BurpExtension
{
	@Override
	public void initialize(MontoyaApi api)
	{
		api.extension().setName("Passkey Raider");

		SettingForm settingForm = new SettingForm(api);
		//api.userInterface().registerSuiteTab("Passkey Raider", settingForm.getUI());

		SwingUtilities.invokeLater(() -> {
			//api.userInterface().registerSuiteTab("Passkey Raider", new SettingForm(api).getUI());
			api.userInterface().registerSuiteTab("Passkey Raider", settingForm.getUI());
		});




		api.userInterface().registerHttpRequestEditorProvider(new MyHttpRequestEditorProvider(settingForm, api));

		//Register proxy handlers with Burp.
		api.proxy().registerRequestHandler(new MyProxyHttpRequestHandler(settingForm, api));
		api.proxy().registerResponseHandler(new MyProxyHttpResponseHandler());
	}
}
