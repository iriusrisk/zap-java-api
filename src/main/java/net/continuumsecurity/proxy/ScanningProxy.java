package net.continuumsecurity.proxy;

import net.continuumsecurity.proxy.model.Context;
import org.zaproxy.clientapi.core.Alert;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

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

    /**
     * Creates a new context with given context name and sets it in scope if @param inScope is true.
     *
     * @param contextName Name of the context.
     * @param inScope     true to set context in scope.
     * @throws ClientApiException
     */
    void createContext(String contextName, boolean inScope) throws ClientApiException;

    /**
     * Adds include regex to the given context.
     *
     * @param contextName Name of the context.
     * @param regex        Regex to include in context.
     * @throws ClientApiException
     */
    void includeRegexInContext(String contextName, Pattern regex) throws ClientApiException;

    /**
     * Adds include parent url to the given content.
     * @param contextName Name of the context.
     * @param parentUrl Parent URL to include in context.
     * @throws ClientApiException
     */
    void includeUrlTreeInContext(String contextName, String parentUrl) throws ClientApiException;

    /**
     * Add exclude regex to the given context.
     * @param contextName Name of the context.
     * @param regex Regex to exclude from context.
     * @throws ClientApiException
     */
    void excludeRegexFromContext(String contextName, Pattern regex) throws ClientApiException;

    /**
     * Add exclude regex to the given context.
     * @param contextName Name of the context.
     * @param parentUrl Parent URL to exclude from context.
     * @throws ClientApiException
     */
    void excludeParentUrlFromContext(String contextName, String parentUrl) throws ClientApiException;

    /**
     * Returns Context details for a given context name.
     * @param contextName Name of context.
     * @return Context details for the given context
     * @throws ClientApiException
     */
    Context getContextInfo(String contextName) throws ClientApiException, IOException;

    /**
     * Returns list of context names.
     * @return List of context names.
     */
    List<String> getContexts() throws ClientApiException;

    /**
     * Sets the given context in or out of scope.
     * @param contextName Name of the context.
     * @param inScope true - Sets the context in scope. false - Sets the context out of scope.
     * @throws ClientApiException
     */
    void setContextInScope(String contextName, boolean inScope) throws ClientApiException;

    /**
     * Returns the list of included regexs for the given context.
     * @param contextName Name of the context.
     * @return List of include regexs.
     * @throws ClientApiException
     */
    List<String> getIncludedRegexs(String contextName) throws ClientApiException;

    /**
     * Returns the list of excluded regexs for the given context.
     * @param contextName Name of the context.
     * @return List of exclude regexs.
     * @throws ClientApiException
     */
    List<String> getExcludedRegexs(String contextName) throws ClientApiException;

    /**
     * Returns the list of Anti CSRF token names.
     * @return List of Anti CSRF token names.
     * @throws ClientApiException
     */
    List<String> getAntiCsrfTokenNames() throws ClientApiException;

    /**
     * Adds an anti CSRF token with the given name, enabled by default.
     * @param tokenName Anti CSRF token name.
     * @throws ClientApiException
     */
    void addAntiCsrfToken(String tokenName) throws ClientApiException;

    /**
     * Removes the anti CSRF token with the given name.
     * @param tokenName Anti CSRF token name.
     * @throws ClientApiException
     */
    void removeAntiCsrfToken(String tokenName) throws ClientApiException;
}
