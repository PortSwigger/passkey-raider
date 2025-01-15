package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

class MyHttpRequestEditorProvider implements HttpRequestEditorProvider
{
	private final SettingForm settingForm;
	private final MontoyaApi api;

	MyHttpRequestEditorProvider(SettingForm settingForm, MontoyaApi api)
	{
		this.settingForm = settingForm;
		this.api = api;
	}

	@Override
	public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext)
	{
		return new MyExtensionProvidedHttpRequestEditor(settingForm, api, creationContext);
	}
}
