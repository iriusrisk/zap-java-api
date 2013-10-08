package net.continuumsecurity.proxy;

import org.openqa.selenium.Proxy;
import org.zaproxy.clientapi.core.Alert;

import java.net.UnknownHostException;
import java.util.List;

public interface ScanningProxy {
    /*
        Clear all results from the scanner
     */
    void clear();

    /*
         Return all results as a list of org.zaproxy.clientapi.core.Alert
     */
    List<Alert> getAlerts();

    /*
        Perform an active scan of everything that was logged by the proxy
     */
    public void scan();

    /*
        Scan a specific URL
     */
    public void scan(String url);

    /*
        Cancel and stop the current scan
     */
    public void cancel();

    /*
        Return the percentage completion of the current scan
     */
    public int getPercentComplete();

    /*
        Return the details of the proxy in Selenium format: org.openqa.selenium.Proxy
    */
    Proxy seleniumProxy() throws UnknownHostException;
}
