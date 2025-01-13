/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp;

import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import static burp.api.montoya.core.HighlightColor.BLUE;

class MyProxyHttpResponseHandler implements ProxyResponseHandler {
	@Override
	public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
		//Highlight all responses that have username in them
        /*if (interceptedResponse.bodyToString().contains("username")) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse, interceptedResponse.annotations().withHighlightColor(BLUE));
        }*/

		return ProxyResponseReceivedAction.continueWith(interceptedResponse);
	}

	@Override
	public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
		return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
	}
}
