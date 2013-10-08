package net.continuumsecurity.proxy;

import net.continuumsecurity.proxy.model.HarEntry;
import net.continuumsecurity.proxy.model.HarRequest;
import org.openqa.selenium.Proxy;

import java.net.UnknownHostException;
import java.util.List;


public interface LoggingProxy {
    /*
        clear all logged data
     */
	void clear();

    /*
        Get the history of all requests and responses, populated into HarEntrys.  A HarEntry consists of a HarRequest and HarResponse, all of the fields
        of these classes, and the classes they contain should be correctly populated.
     */
	List<HarEntry> getHistory();

    /*
        Search through all the HarRequests for the given regex.  The search should be performed on all request headers as well as post body.
        When a match is found, return the entire HarEntry (request and response).
     */
	List<HarEntry> findInRequestHistory(List<HarEntry> history, String regex);

    /*
       Search through all HarResponses for the given regex, this must include response headers and content.
     */
	List<HarEntry> findInResponseHistory(List<HarEntry> history, String regex);

    /*
       Make a request using the HarRequest data and follow redirects if specified.  Return all the resulting request/responses.
     */
	List<HarEntry> makeRequest(HarRequest request, boolean followRedirect) throws Exception;

    /*
       Return the details of the proxy in Selenium format: org.openqa.selenium.Proxy
     */
	Proxy seleniumProxy() throws UnknownHostException;
}
