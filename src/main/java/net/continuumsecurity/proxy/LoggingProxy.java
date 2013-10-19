package net.continuumsecurity.proxy;


import edu.umass.cs.benchlab.har.HarEntry;
import edu.umass.cs.benchlab.har.HarRequest;
import org.openqa.selenium.Proxy;

import java.net.UnknownHostException;
import java.util.List;


public interface LoggingProxy {
    /*
        Call newSession(string, string) on the ZAP api
    */
	void clear();

    /*
        Get the history of all requests and responses, populated into HarEntrys.  A HarEntry consists of a HarRequest and HarResponse, all of the fields
        of these classes, and the classes they contain should be correctly populated.
     */
	List<HarEntry> getHistory();

    /*
        As above, but only get a range of records
     */
    List<HarEntry> getHistory(int start, int end);

    /*
        How many records are available to fetch?
     */
    int getHistoryCount();

    /*
        Search through all the HarRequests for the given regex.  The search should be performed on all request headers as well as post body.
        When a match is found, return the entire HarEntry (request and response).

        Can't use the ZAP search api methods such as: urlsByRequestRegex (regex* baseurl start count ), because these just return the URLs, not the entire request/response pair
     */
	List<HarEntry> findInRequestHistory(List<HarEntry> history, String regex);

    /*
       Search through all HarResponses for the given regex, this must include response headers and content.
     */
	List<HarEntry> findInResponseHistory(List<HarEntry> history, String regex);

    /*
       Make a request using the HarRequest data and follow redirects if specified.  Return all the resulting request/responses.
       This could be implemented through Apache Commons HttpClient or HtmlUnit.
     */
	List<HarEntry> makeRequest(HarRequest request, boolean followRedirect) throws Exception;

    /*
       Return the details of the proxy in Selenium format: org.openqa.selenium.Proxy
     */
	Proxy seleniumProxy() throws UnknownHostException;
}
