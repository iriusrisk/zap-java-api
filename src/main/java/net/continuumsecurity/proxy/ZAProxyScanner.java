package net.continuumsecurity.proxy;

import edu.umass.cs.benchlab.har.HarEntry;
import edu.umass.cs.benchlab.har.HarLog;
import edu.umass.cs.benchlab.har.HarRequest;
import edu.umass.cs.benchlab.har.tools.HarFileReader;
import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonGenerator;
import org.openqa.selenium.Proxy;
import org.zaproxy.clientapi.core.*;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ZAProxyScanner implements ScanningProxy {

    private final ExtendedClientApi clientApi;

    private final Proxy seleniumProxy;

    public ZAProxyScanner(String zapPath,String host, int port) throws IllegalArgumentException, ProxyException {

        this(host,port);
    }

    public ZAProxyScanner(String host, int port) throws IllegalArgumentException, ProxyException {
        validateHost(host);
        validatePort(port);

        clientApi = new ExtendedClientApi(host, port);

        if (!isExtendedApiAvailable()) {
            throw new IllegalStateException("Required add-on \"extendedapi\" not installed in target ZAP.");
        }

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

    private boolean isExtendedApiAvailable() throws ProxyException {
        try {
            return clientApi.isExtendedApiAvailable();
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<Alert> getAlerts() throws ProxyException {
        try {
            return clientApi.getAlerts("", -1, -1);
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
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
            return clientApi.getAlertsCount("");
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

    public int getPercentComplete() throws ProxyException {
        try {
            return clientApi.getPercentComplete();
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public void clear() throws ProxyException {
        try {
            clientApi.core.newSession("", "false");
        } catch (ClientApiException e) {
            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> getHistory() throws ProxyException {
        try {
            return clientApi.getMessagesHar("", -1, -1);
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> getHistory(int start, int count) throws ProxyException {
        try {
            return clientApi.getMessagesHar("", start, count);
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public int getHistoryCount() throws ProxyException {
        try {
            return clientApi.getMessagesCount("");
        } catch (ClientApiException e) {

            e.printStackTrace();
            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> findInRequestHistory(String regex) throws ProxyException {
        try {
            return clientApi.getMessagesHarByRequestRegex(regex, "", -1, -1);
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> findInResponseHistory(String regex) throws ProxyException {
        try {
            return clientApi.getMessagesHarByResponseRegex(regex, "", -1, -1);
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public List<HarEntry> makeRequest(HarRequest request, boolean followRedirect) throws ProxyException {
        try {
            return clientApi.makeRequestHar(request, followRedirect);
        } catch (ClientApiException e) {
            e.printStackTrace();

            throw new ProxyException("Error occurred while accessing ZAP.", e);
        }
    }

    public Proxy getSeleniumProxy() throws UnknownHostException {
        return seleniumProxy;
    }

    private static class ExtendedClientApi extends ClientApi {

        public final ExtendedApi extendedApi;

        private final java.net.Proxy proxy;
        private final boolean debug;
        private PrintStream debugStream = System.out;

        public ExtendedClientApi(String zapAddress, int zapPort) {
            this(zapAddress, zapPort, false);
        }

        public ExtendedClientApi(String zapAddress, int zapPort, boolean debug) {
            super(zapAddress, zapPort);

            this.debug = debug;
            proxy = new java.net.Proxy(java.net.Proxy.Type.HTTP, new InetSocketAddress(zapAddress, zapPort));

            extendedApi = new ExtendedApi(this);
        }

        @Override
        public void setDebugStream(PrintStream debugStream) {
            super.setDebugStream(debugStream);
            this.debugStream = debugStream;
        }

        public boolean isExtendedApiAvailable() throws ClientApiException {
            try {
                return getBoolean(extendedApi.available(), false);
            } catch (ClientApiException e) {
                if ("no_implementor".equals(e.getCode())) {
                    return false;
                }
                throw e;
            }
        }

        public int getAlertsCount(String baseUrl) throws ClientApiException {
            return getInteger(extendedApi.alertsCount(baseUrl));
        }

        public int getPercentComplete() throws ClientApiException {
            return getInteger(ascan.status());
        }

        public List<HarEntry> getMessagesHar(String baseUrl, int start, int count) throws ClientApiException {
            return getHarEntries(getHarLog(extendedApi.messagesHar(baseUrl, Integer.toString(start), Integer.toString(count))));
        }

        public int getMessagesCount(String baseUrl) throws ClientApiException {
            return getInteger(extendedApi.messagesCount(baseUrl));
        }

        public List<HarEntry> getMessagesHarByRequestRegex(String regex, String baseUrl, int start, int count)
                throws ClientApiException {
            return getHarEntries(getHarLog(extendedApi.harsByRequestRegex(
                    regex,
                    baseUrl,
                    Integer.toString(start),
                    Integer.toString(count))));
        }

        public List<HarEntry> getMessagesHarByResponseRegex(String regex, String baseUrl, int start, int count)
                throws ClientApiException {
            return getHarEntries(getHarLog(extendedApi.harsByResponseRegex(
                    regex,
                    baseUrl,
                    Integer.toString(start),
                    Integer.toString(count))));
        }

        public List<HarEntry> makeRequestHar(HarRequest request, boolean followRedirect) throws ClientApiException {
            return getHarEntries(getHarLog(extendedApi.makeRequestHar(
                    convertHarRequestToString(request),
                    Boolean.toString(followRedirect))));
        }

        public String convertHarRequestToString(HarRequest request) throws ClientApiException {
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

        private static HarLog getHarLog(byte[] bytesHarLog) throws ClientApiException {
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

        private static List<HarEntry> getHarEntries(HarLog harLog) {
            if (harLog == null) {
                throw new IllegalArgumentException("Parameter harLog must not be null.");
            }
            return harLog.getEntries().getEntries();
        }

        @Override
        public ApiResponse callApi(String component, String type, String method, Map<String, String> params)
                throws ClientApiException {
            Map<String, String> encodedParams = null;
            if (params != null) {
                encodedParams = new HashMap<String, String>();
                for (Map.Entry<String, String> p : params.entrySet()) {
                    String paramValue = p.getValue();
                    if (paramValue != null) {
                        paramValue = encodeQueryParam(paramValue);
                    }
                    encodedParams.put(encodeQueryParam(p.getKey()), paramValue);
                }
            }
            return super.callApi(component, type, method, encodedParams);
        }

        private static String encodeQueryParam(String param) {
            try {
                return URLEncoder.encode(param, "UTF-8");
            } catch (UnsupportedEncodingException ignore) {
                // UTF-8 is a standard charset.
            }
            return param;
        }

        protected byte[] callApiOther(String component, String type, String method, Map<String, String> params)
                throws ClientApiException {
            StringBuilder sb = new StringBuilder(250);
            sb.append("http://zap/other/").append(component).append('/').append(type).append('/').append(method).append('/');
            if (params != null) {
                sb.append('?');
                for (Map.Entry<String, String> p : params.entrySet()) {
                    sb.append(encodeQueryParam(p.getKey()));
                    sb.append('=');
                    if (p.getValue() != null) {
                        sb.append(encodeQueryParam(p.getValue()));
                    }
                    sb.append('&');
                }
            }

            try {
                URL url = new URL(sb.toString());
                if (debug) {
                    debugStream.println("Open URL: " + url);
                }
                HttpURLConnection uc = (HttpURLConnection) url.openConnection(proxy);
                InputStream in = uc.getInputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                try {
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                } catch (IOException e) {
                    throw new ClientApiException(e);
                } finally {
                    in.close();
                    out.close();
                }
                System.out.println("Length: "+out.toByteArray().length);
                return out.toByteArray();

            } catch (Exception e) {
                throw new ClientApiException(e);
            }
        }

        private static boolean getBoolean(ApiResponse response, boolean defaultValue) {
            try {
                return Boolean.valueOf((((ApiResponseElement) response).getValue())).booleanValue();
            } catch (Exception e) {
                return defaultValue;
            }
        }

        private static int getInteger(ApiResponse response) throws ClientApiException {
            try {
                return Integer.valueOf((((ApiResponseElement) response).getValue())).intValue();
            } catch (Exception e) {
                throw new ClientApiException("Unable to get integer from response.");
            }
        }

        private class ExtendedApi {

            private ExtendedClientApi api = null;

            public ExtendedApi(ExtendedClientApi api) {
                this.api = api;
            }

            public ApiResponse available() throws ClientApiException {
                Map<String, String> map = null;
                return api.callApi("extendedApi", "view", "available", map);
            }

            public ApiResponse messagesCount(String baseurl) throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("baseurl", baseurl);
                return api.callApi("extendedApi", "view", "messagesCount", map);
            }

            public ApiResponse alertsCount(String baseurl) throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("baseurl", baseurl);
                return api.callApi("extendedApi", "view", "alertsCount", map);
            }

            @SuppressWarnings("unused")
            public ApiResponse messagesByUrlRegex(String regex, String baseurl, String start, String count)
                    throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("regex", regex);
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApi("extendedApi", "view", "messagesByUrlRegex", map);
            }

            @SuppressWarnings("unused")
            public ApiResponse messagesByRequestRegex(String regex, String baseurl, String start, String count)
                    throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("regex", regex);
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApi("extendedApi", "view", "messagesByRequestRegex", map);
            }

            @SuppressWarnings("unused")
            public ApiResponse messagesByResponseRegex(String regex, String baseurl, String start, String count)
                    throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("regex", regex);
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApi("extendedApi", "view", "messagesByResponseRegex", map);
            }

            @SuppressWarnings("unused")
            public ApiResponse messagesByHeaderRegex(String regex, String baseurl, String start, String count)
                    throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("regex", regex);
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApi("extendedApi", "view", "messagesByHeaderRegex", map);
            }

            public byte[] messagesHar(String baseurl, String start, String count) throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApiOther("extendedApi", "other", "messagesHar", map);
            }

            @SuppressWarnings("unused")
            public byte[] harsByUrlRegex(String regex, String baseurl, String start, String count) throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("regex", regex);
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApiOther("extendedApi", "other", "harsByUrlRegex", map);
            }

            public byte[] harsByRequestRegex(String regex, String baseurl, String start, String count)
                    throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("regex", regex);
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApiOther("extendedApi", "other", "harsByRequestRegex", map);
            }

            public byte[] harsByResponseRegex(String regex, String baseurl, String start, String count)
                    throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("regex", regex);
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApiOther("extendedApi", "other", "harsByResponseRegex", map);
            }

            @SuppressWarnings("unused")
            public byte[] harsByHeaderRegex(String regex, String baseurl, String start, String count) throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("regex", regex);
                map.put("baseurl", baseurl);
                map.put("start", start);
                map.put("count", count);
                return api.callApiOther("extendedApi", "other", "harsByHeaderRegex", map);
            }

            public byte[] makeRequestHar(String harrequest, String followredirects) throws ClientApiException {
                Map<String, String> map = null;
                map = new HashMap<String, String>();
                map.put("harRequest", harrequest);
                map.put("followRedirects", followredirects);
                return api.callApiOther("extendedApi", "other", "makeRequestHar", map);
            }
        }
    }
}
