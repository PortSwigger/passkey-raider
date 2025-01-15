package burp;

import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

class MyProxyHttpResponseHandler implements ProxyResponseHandler {
	@Override
	public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
		return ProxyResponseReceivedAction.continueWith(interceptedResponse);
	}

	@Override
	public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
		return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
	}
}
