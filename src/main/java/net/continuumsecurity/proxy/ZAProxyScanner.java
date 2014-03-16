package net.continuumsecurity.proxy;

import edu.umass.cs.benchlab.har.HarEntry;
import edu.umass.cs.benchlab.har.HarLog;
import edu.umass.cs.benchlab.har.HarRequest;
import edu.umass.cs.benchlab.har.tools.HarFileReader;
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

public class ZAProxyScanner implements ScanningProxy, Spider {

    private static final String MINIMUM_ZAP_DAILY_VERSION = "D-2013-11-17";
    // TODO Update with valid version number when a new main ZAP release is available.
    private static final String MINIMUM_ZAP_VERSION = "";

    private final ClientApi clientApi;

    private final Proxy seleniumProxy;

    public ZAProxyScanner(String zapPath,String host, int port) throws IllegalArgumentException, ProxyException {

        this(host,port);
    }

    public ZAProxyScanner(String host, int port) throws IllegalArgumentException, ProxyException {
        validateHost(host);
        validatePort(port);

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
            if (zapVersion.startsWith("D-")) {
                minimumRequiredZapVersion = zapVersion.compareTo(MINIMUM_ZAP_DAILY_VERSION) >= 0;
            } else {
                minimumRequiredZapVersion = compareZapVersions(zapVersion, MINIMUM_ZAP_VERSION) >= 0;
            }

            if (!minimumRequiredZapVersion) {
                throw new IllegalStateException("Minimum required ZAP version not met, expected >= \""
                        + MINIMUM_ZAP_DAILY_VERSION + "\" or >= \"" + MINIMUM_ZAP_VERSION + "\" but got: " + zapVersion);
            }
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    @Override
    public void setEnableScanners(String ids, boolean enabled) throws ProxyException {
        try {
            if (enabled) {
                clientApi.ascan.enableScanners(ids);
            } else {
                clientApi.ascan.disableScanners(ids);
            }
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    @Override
    public void disableAllScanners() throws ProxyException {
        try {
            clientApi.pscan.setEnabled("false");
            clientApi.ascan.disableAllScanners();
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    @Override
    public void setEnablePassiveScan(boolean enabled) throws ProxyException {
        try {
            clientApi.pscan.setEnabled(Boolean.toString(enabled));
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<Alert> getAlerts() throws ProxyException {
        return getAlerts(-1, -1);
    }

    public List<Alert> getAlerts(int start, int count) throws ProxyException {
        try {
            return clientApi.getAlerts("", start, count);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public int getAlertsCount() throws ProxyException {
        try {
            return ClientApiUtils.getInteger(clientApi.core.numberOfAlerts(""));
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public void scan(String url) throws ProxyException {
         try {
            clientApi.ascan.scan(url, "true", "false");
         } catch (ClientApiException e) {
             e.printStackTrace();
             throw new ProxyException("Error occurred while accessing ZAP.", e);
         }
     }

    public int getScanStatus() throws ProxyException {
        try {
            return ClientApiUtils.getInteger(clientApi.ascan.status());
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public void clear() throws ProxyException {
        try {
            clientApi.core.newSession("", "true");
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> getHistory() throws ProxyException {
        return getHistory(-1, -1);
    }

    public List<HarEntry> getHistory(int start, int count) throws ProxyException {
        try {
            return ClientApiUtils.getHarEntries(clientApi.core.messagesHar("", Integer.toString(start), Integer.toString(count)));
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public int getHistoryCount() throws ProxyException {
        try {
            return ClientApiUtils.getInteger(clientApi.core.numberOfMessages(""));
        } catch (ClientApiException e) {

            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> findInRequestHistory(String regex) throws ProxyException {
        try {
            return ClientApiUtils.getHarEntries(clientApi.search.harByRequestRegex(regex, "", "-1", "-1"));
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> findInResponseHistory(String regex) throws ProxyException {
        try {
            return ClientApiUtils.getHarEntries(clientApi.search.harByResponseRegex(regex, "", "-1", "-1"));
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> makeRequest(HarRequest request, boolean followRedirect) throws ProxyException {
        try {
            String harRequestStr = ClientApiUtils.convertHarRequestToString(request);
            return ClientApiUtils.getHarEntries(clientApi.core.sendHarRequest(harRequestStr, Boolean.toString(followRedirect)));
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public Proxy getSeleniumProxy() throws UnknownHostException {
        return seleniumProxy;
    }

    private static int compareZapVersions(String version, String otherVersion) {
        final String[] v1 = version.split("\\.");
        final String[] v2 = otherVersion.split("\\.");

        for (int i = 0; i < v1.length; i++) {
            if (i >= v2.length) {
                return 1;
            }
            if (v1[i].equals(v2[i])) {
                continue;
            }
            return (Integer.parseInt(v1[i]) - Integer.parseInt(v2[i]));
        }

        return -1;
    }

    @Override
    public void spider(String url) {
        try {
            clientApi.spider.scan(url);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    @Override
    public void excludeFromScan(String regex) {
        try {
            clientApi.spider.excludeFromScan(regex);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    @Override
    public void setMaxDepth(int depth) {
        try {
            clientApi.spider.setOptionMaxDepth(depth);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    @Override
    public void setPostForms(boolean post) {
        try {
            clientApi.spider.setOptionPostForm(post);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    @Override
    public void setThreadCount(int threads) {
        try {
            clientApi.spider.setOptionThreadCount(threads);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }


    @Override
    public int getSpiderStatus() {
        try {
            return ClientApiUtils.getInteger(clientApi.spider.status());
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    @Override
    public List<String> getSpiderResults() {
        List<String> results = new ArrayList<String>();
        try {
            ApiResponseList responseList = (ApiResponseList)clientApi.spider.results();
            for (ApiResponse response : responseList.getItems()) {
                results.add(((ApiResponseElement)response).getValue());
            }
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
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
}
