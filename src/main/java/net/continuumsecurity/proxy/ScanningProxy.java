package net.continuumsecurity.proxy;

import org.zaproxy.clientapi.core.Alert;

import java.util.List;

public interface ScanningProxy extends LoggingProxy {

    /*
         Return all results as a list of org.zaproxy.clientapi.core.Alert
     */
    List<Alert> getAlerts();

    /*
        As above, but for a specific range of records
     */
    List<Alert> getAlerts(int start, int end);

    /*
        The number of available alerts
     */
    int getAlertsCount();

    /*
        Perform an active scan of everything that was logged by the proxy
     */
    public void scan(String url);

}
