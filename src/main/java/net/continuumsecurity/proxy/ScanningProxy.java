package net.continuumsecurity.proxy;

import org.zaproxy.clientapi.core.Alert;

import java.util.List;

public interface ScanningProxy extends LoggingProxy {

    /*
         Return all results as a list of org.zaproxy.clientapi.core.Alert
     */
    List<Alert> getAlerts() throws ProxyException;

    /*
        As above, but for a specific range of records
     */
    List<Alert> getAlerts(int start, int count) throws ProxyException;

    /*
        The number of available alerts
     */
    int getAlertsCount() throws ProxyException;

    public void deleteAlerts() throws ProxyException;
    /*
        Perform an active scan of everything that was logged by the proxy
     */
    public void scan(String url) throws ProxyException;

    /*
        Return the percentage completion of the current scan
     */
    public int getScanProgress(int scanId) throws ProxyException;

    public int getLastScannerScanId() throws ProxyException;

    public byte[] getXmlReport() throws ProxyException;

    public byte[] getHtmlReport() throws ProxyException;

    void setScannerAttackStrength(String scannerId, String strength) throws ProxyException;

    void setScannerAlertThreshold(String scannerId, String threshold) throws ProxyException;

    public void setEnableScanners(String ids, boolean enabled) throws ProxyException;

    public void disableAllScanners() throws ProxyException;

    public void enableAllScanners() throws ProxyException;

    public void setEnablePassiveScan(boolean enabled) throws ProxyException;

    public void excludeFromScanner(String regex) throws ProxyException;

    /**
     * Shuts down ZAP.
     * @throws ProxyException
     */
    public void shutdown() throws ProxyException;
}
