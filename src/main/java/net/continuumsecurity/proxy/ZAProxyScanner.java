package net.continuumsecurity.proxy;

import edu.umass.cs.benchlab.har.HarEntry;
import edu.umass.cs.benchlab.har.HarLog;
import edu.umass.cs.benchlab.har.HarRequest;
import edu.umass.cs.benchlab.har.tools.HarFileReader;
import net.continuumsecurity.proxy.model.ScanResponse;
import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonGenerator;
import org.openqa.selenium.Proxy;
import org.zaproxy.clientapi.core.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class ZAProxyScanner implements ScanningProxy, Spider {
    Logger log = Logger.getLogger(ZAProxyScanner.class.getName());

    private static final String MINIMUM_ZAP_VERSION = "2.4.3";

    private final ClientApi clientApi;
    private final Proxy seleniumProxy;
    private final String apiKey;


    public ZAProxyScanner(String host, int port, String apiKey) throws IllegalArgumentException, ProxyException {
        validateHost(host);
        validatePort(port);
        this.apiKey = apiKey;

        clientApi = new ClientApi(host, port);
        validateMinimumRequiredZapVersion();

        seleniumProxy = new Proxy();
        seleniumProxy.setProxyType(Proxy.ProxyType.PAC);
        StringBuilder strBuilder = new StringBuilder();
        strBuilder.append("http://").append(host).append(":").append(port).append("/proxy.pac");
        seleniumProxy.setProxyAutoconfigUrl(strBuilder.toString());
    }

    private static void validateHost(String host) {
        if (host == null) {
            throw new IllegalArgumentException("Parameter host must not be null.");
        }
        if (host.isEmpty()) {
            throw new IllegalArgumentException("Parameter host must not be empty.");
        }
    }

    private static void validatePort(int port) {
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException("Parameter port must be between 1 and 65535.");
        }
    }

    private void validateMinimumRequiredZapVersion() throws ProxyException {
        try {
            final String zapVersion = ((ApiResponseElement) clientApi.core.version()).getValue();

            boolean minimumRequiredZapVersion = false;
            minimumRequiredZapVersion = validZAPVersion(MINIMUM_ZAP_VERSION, zapVersion);

            if (!minimumRequiredZapVersion) {
                throw new IllegalStateException("Minimum required ZAP version not met, expected >= \""
                        + MINIMUM_ZAP_VERSION + "\" but got: " + zapVersion);
            }
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void setScannerAttackStrength(String scannerId, String strength) throws ProxyException {
        try {
            clientApi.ascan.setScannerAttackStrength(apiKey,scannerId, strength,null);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred for setScannerAttackStrength", e);
        }
    }

    @Override
    public void setScannerAlertThreshold(String scannerId, String threshold) throws ProxyException {
        try {
            clientApi.ascan.setScannerAlertThreshold(apiKey, scannerId, threshold,null);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void setEnableScanners(String ids, boolean enabled) throws ProxyException {
        try {
            if (enabled) {
                clientApi.ascan.enableScanners(apiKey,ids);
            } else {
                clientApi.ascan.disableScanners(apiKey,ids);
            }
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void disableAllScanners() throws ProxyException {
        try {
            ApiResponse response = clientApi.pscan.setEnabled(apiKey,"false");
            response = clientApi.ascan.disableAllScanners(apiKey,null);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void enableAllScanners() throws ProxyException {
        try {
            clientApi.pscan.setEnabled(apiKey,"true");
            clientApi.ascan.enableAllScanners(apiKey,null);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void setEnablePassiveScan(boolean enabled) throws ProxyException {
        try {
            clientApi.pscan.setEnabled(apiKey,Boolean.toString(enabled));
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    public List<Alert> getAlerts() throws ProxyException {
        return getAlerts(-1, -1);
    }

    public void deleteAlerts() throws ProxyException {
        try {
            clientApi.core.deleteAllAlerts(apiKey);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    public byte[] getXmlReport() {
        try {
            return clientApi.core.xmlreport(apiKey);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public byte[] getHtmlReport() throws ProxyException {
        try {
            return clientApi.core.htmlreport(apiKey);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    public List<Alert> getAlerts(int start, int count) throws ProxyException {
        try {
            return clientApi.getAlerts("", start, count);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }


    public int getAlertsCount() throws ProxyException {
        try {
            return ClientApiUtils.getInteger(clientApi.core.numberOfAlerts(""));
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    public void scan(String url) throws ProxyException {
         try {
            clientApi.ascan.scan(apiKey,url, "true", "false",null,null,null);
         } catch (ClientApiException e) {
             e.printStackTrace();
             throw new ProxyException(e);
         }
     }

    public int getScanProgress(int id) throws ProxyException {
        try {
            ApiResponseList response = (ApiResponseList)clientApi.ascan.scans();
            return new ScanResponse(response).getScanById(id).getProgress();
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    public void clear() throws ProxyException {
        try {
            clientApi.ascan.removeAllScans(apiKey);
            clientApi.core.newSession(apiKey,"","");
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    public List<HarEntry> getHistory() throws ProxyException {
        return getHistory(-1, -1);
    }

    public List<HarEntry> getHistory(int start, int count) throws ProxyException {
        try {
            return ClientApiUtils.getHarEntries(clientApi.core.messagesHar(apiKey,"", Integer.toString(start), Integer.toString(count)));
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException(e);
        }
    }

    public int getHistoryCount() throws ProxyException {
        try {
            return ClientApiUtils.getInteger(clientApi.core.numberOfMessages(""));
        } catch (ClientApiException e) {

            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    public List<HarEntry> findInResponseHistory(String regex,List<HarEntry> entries) {
        List<HarEntry> found = new ArrayList<HarEntry>();
        for (HarEntry entry : entries) {
            if (entry.getResponse().getContent() != null) {
                String content = entry.getResponse().getContent().getText();
                if ("base64".equalsIgnoreCase(entry.getResponse().getContent().getEncoding())) {
                    content = new String(Base64.decodeBase64(content));
                }
                if (content.contains(regex)) {
                    found.add(entry);
                }
            }
        }
        return found;
    }


    public List<HarEntry> findInRequestHistory(String regex) throws ProxyException {
        try {
            return ClientApiUtils.getHarEntries(clientApi.search.harByRequestRegex(apiKey,regex, "", "-1", "-1"));
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException(e);
        }
    }

    public List<HarEntry> findInResponseHistory(String regex) throws ProxyException {
        try {
            return ClientApiUtils.getHarEntries(clientApi.search.harByResponseRegex(apiKey,regex, "", "-1", "-1"));
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException(e);
        }
    }

    public List<HarEntry> makeRequest(HarRequest request, boolean followRedirect) throws ProxyException {
        try {
            String harRequestStr = ClientApiUtils.convertHarRequestToString(request);
            return ClientApiUtils.getHarEntries(clientApi.core.sendHarRequest(apiKey,harRequestStr, Boolean.toString(followRedirect)));
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException(e);
        }
    }

    public Proxy getSeleniumProxy() throws UnknownHostException {
        return seleniumProxy;
    }

    private static boolean validZAPVersion(String expected, String given) {
        final String[] expectedVersion = expected.split("\\.");
        final String[] givenVersion = given.split("\\.");

        for (int i = 0; i < givenVersion.length; i++) {
            if (i < expectedVersion.length) {
                if (Integer.parseInt(givenVersion[i]) < Integer.parseInt(expectedVersion[i])) return false;
            }
        }

        return true;
    }

    @Override
    public void spider(String url, Integer maxChildren, boolean recurse, String contextName) {
        String contextNameString = contextName == null ? "Default Context" : contextName; //Something must be specified else zap throws an exception
        String maxChildrenString = maxChildren == null ? null : String.valueOf(maxChildren);
        try {
            clientApi.spider.scan(apiKey,url,maxChildrenString,  String.valueOf(recurse), contextNameString);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void excludeFromSpider(String regex) {
        try {
            clientApi.spider.excludeFromScan(apiKey,regex);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void excludeFromScanner(String regex) {
        try {
            clientApi.ascan.excludeFromScan(apiKey, regex);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void setMaxDepth(int depth) {
        try {
            clientApi.spider.setOptionMaxDepth(apiKey,depth);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void setPostForms(boolean post) {
        try {
            clientApi.spider.setOptionPostForm(apiKey,post);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public void setThreadCount(int threads) {
        try {
            clientApi.spider.setOptionThreadCount(apiKey,threads);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public int getLastSpiderScanId() {
        try {
            ApiResponseList response = (ApiResponseList)clientApi.spider.scans();
            return new ScanResponse(response).getLastScan().getId();
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public int getLastScannerScanId() {
        try {
            ApiResponseList response = (ApiResponseList)clientApi.ascan.scans();
            return new ScanResponse(response).getLastScan().getId();
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public int getSpiderProgress(int id) {
        try {
            ApiResponseList response = (ApiResponseList)clientApi.spider.scans();
            return new ScanResponse(response).getScanById(id).getProgress();
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }

    @Override
    public List<String> getSpiderResults(int id) {
        List<String> results = new ArrayList<String>();
        try {
            ApiResponseList responseList = (ApiResponseList)clientApi.spider.results(Integer.toString(id));
            for (ApiResponse response : responseList.getItems()) {
                results.add(((ApiResponseElement)response).getValue());
            }
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }

        return results;
    }

    private static class ClientApiUtils {

        private ClientApiUtils() {
        }

        public static int getInteger(ApiResponse response) throws ClientApiException {
            try {
                return Integer.parseInt(((ApiResponseElement) response).getValue());
            } catch (Exception e) {
                throw new ClientApiException("Unable to get integer from response.");
            }
        }

        public static String convertHarRequestToString(HarRequest request) throws ClientApiException {
            try {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                JsonGenerator g = new JsonFactory().createJsonGenerator(os);
                g.writeStartObject();
                request.writeHar(g);
                g.close();
                return os.toString("UTF-8");
            } catch (IOException e) {
                throw new ClientApiException(e);
            }
        }

        public static HarLog createHarLog(byte[] bytesHarLog) throws ClientApiException {
            try {
                if (bytesHarLog.length == 0) {
                    throw new ClientApiException("Unexpected ZAP response.");
                }
                HarFileReader reader = new HarFileReader();
                return reader.readHarFile(new ByteArrayInputStream(bytesHarLog), null);
            } catch (IOException e) {
                throw new ClientApiException(e);
            }
        }

        public static List<HarEntry> getHarEntries(byte[] bytesHarLog) throws ClientApiException {
            return createHarLog(bytesHarLog).getEntries().getEntries();
        }

    }

    /**
     * Shuts down ZAP.
     * @throws ProxyException
     */
    @Override
    public void shutdown() {
        try {
            clientApi.core.shutdown(apiKey);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException(e);
        }
    }
}
