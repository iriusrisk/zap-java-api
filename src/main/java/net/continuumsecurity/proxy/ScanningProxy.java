package net.continuumsecurity.proxy;

import net.continuumsecurity.proxy.model.Context;
import org.zaproxy.clientapi.core.Alert;

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
     * @throws ProxyException
     */
    void createContext(String contextName, boolean inScope) throws ProxyException;

    /**
     * Adds include regex to the given context.
     *
     * @param contextName Name of the context.
     * @param regex        Regex to include in context.
     * @throws ProxyException
     */
    void includeRegexInContext(String contextName, Pattern regex) throws ProxyException;

    /**
     * Adds include parent url to the given content.
     * @param contextName Name of the context.
     * @param parentUrl Parent URL to include in context.
     * @throws ProxyException
     */
    void includeUrlTreeInContext(String contextName, String parentUrl) throws ProxyException;

    /**
     * Add exclude regex to the given context.
     * @param contextName Name of the context.
     * @param regex Regex to exclude from context.
     * @throws ProxyException
     */
    void excludeRegexFromContext(String contextName, Pattern regex) throws ProxyException;

    /**
     * Add exclude regex to the given context.
     * @param contextName Name of the context.
     * @param parentUrl Parent URL to exclude from context.
     * @throws ProxyException
     */
    void excludeParentUrlFromContext(String contextName, String parentUrl) throws ProxyException;

    /**
     * Returns Context details for a given context name.
     * @param contextName Name of context.
     * @return Context details for the given context
     * @throws ProxyException
     */
    Context getContextInfo(String contextName) throws ProxyException, IOException;

    /**
     * Returns list of context names.
     * @return List of context names.
     * @throws ProxyException
     */
    List<String> getContexts() throws ProxyException;

    /**
     * Sets the given context in or out of scope.
     * @param contextName Name of the context.
     * @param inScope true - Sets the context in scope. false - Sets the context out of scope.
     * @throws ProxyException
     */
    void setContextInScope(String contextName, boolean inScope) throws ProxyException;

    /**
     * Returns the list of included regexs for the given context.
     * @param contextName Name of the context.
     * @return List of include regexs.
     * @throws ProxyException
     */
    List<String> getIncludedRegexs(String contextName) throws ProxyException;

    /**
     * Returns the list of excluded regexs for the given context.
     * @param contextName Name of the context.
     * @return List of exclude regexs.
     * @throws ProxyException
     */
    List<String> getExcludedRegexs(String contextName) throws ProxyException;

    /**
     * Returns the list of Anti CSRF token names.
     * @return List of Anti CSRF token names.
     * @throws ProxyException
     */
    List<String> getAntiCsrfTokenNames() throws ProxyException;

    /**
     * Adds an anti CSRF token with the given name, enabled by default.
     * @param tokenName Anti CSRF token name.
     * @throws ProxyException
     */
    void addAntiCsrfToken(String tokenName) throws ProxyException;

    /**
     * Removes the anti CSRF token with the given name.
     * @param tokenName Anti CSRF token name.
     * @throws ProxyException
     */
    void removeAntiCsrfToken(String tokenName) throws ProxyException;
}
