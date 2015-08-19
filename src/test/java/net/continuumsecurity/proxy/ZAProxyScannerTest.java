package net.continuumsecurity.proxy;


import edu.umass.cs.benchlab.har.HarEntry;
import edu.umass.cs.benchlab.har.HarRequest;
import edu.umass.cs.benchlab.har.HarResponse;
import net.continuumsecurity.proxy.model.AuthenticationMethod;
import net.continuumsecurity.proxy.model.Context;
import net.continuumsecurity.proxy.model.User;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.zaproxy.clientapi.core.Alert;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.*;

public class ZAProxyScannerTest {
    static WebDriver driver;
    static ZAProxyScanner zaproxy;
    static String HOST = "127.0.0.1";
    static int PORT = 8888;
    static String CHROME = "src/test/resources/chromedriver-mac";
    static String BASEURL = "http://localhost:9090/";
    public static final String TEST_CONTEXT_NAME = "Test Context";
    public static final Pattern INCLUDE_REGEX_PATTERN = Pattern.compile("http://test-me.com/*");
    public static final Pattern EXCLUDE_REGEX_PATTERN = Pattern.compile("https://do-not-test-me.com/*");
    public static final String INCLUDE_PARENT_URL = "http://test-me-too.com";
    public static final String EXCLUDE_PARENT_URL = "https://do-not-test-me-too.com";

    @BeforeClass
    public static void configure() throws Exception {
        zaproxy = new ZAProxyScanner(HOST, PORT, "");
        DesiredCapabilities capabilities = new DesiredCapabilities();
        capabilities.setCapability(CapabilityType.PROXY, zaproxy.getSeleniumProxy());

        System.setProperty("webdriver.chrome.driver", CHROME);
        driver = new ChromeDriver(capabilities);
        driver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);

    }

    @AfterClass
    public static void tearDown() throws Exception {
        driver.close();
    }

    @Before
    public void setup() throws ProxyException {
        zaproxy.clear();
        driver.manage().deleteAllCookies();
    }

    @Test
    public void testContext() throws ProxyException, IOException {
        List<String> contexts = zaproxy.getContexts();
        int numberOfContexts = contexts.size();

        String contextName = TEST_CONTEXT_NAME + " - " + RandomStringUtils.randomAlphanumeric(3);

        zaproxy.createContext(contextName, false);
        zaproxy.setContextInScope(contextName, true);

        contexts = zaproxy.getContexts();
        assertTrue(contexts.contains(contextName));
        assertEquals(numberOfContexts + 1, contexts.size());

        Context context = zaproxy.getContextInfo(contextName);
        assertThat(context, notNullValue());
        List<String> includedRegexs = zaproxy.getIncludedRegexs(contextName);
        assertThat(includedRegexs, nullValue());
        List<String> excludedRegexs = zaproxy.getExcludedRegexs(contextName);
        assertThat(excludedRegexs, nullValue());

        zaproxy.includeRegexInContext(contextName, INCLUDE_REGEX_PATTERN);
        zaproxy.includeUrlTreeInContext(contextName, INCLUDE_PARENT_URL);

        zaproxy.excludeRegexFromContext(contextName, EXCLUDE_REGEX_PATTERN);
        zaproxy.excludeParentUrlFromContext(contextName, EXCLUDE_PARENT_URL);

        context = zaproxy.getContextInfo(contextName);
        assertThat(context.getIncludedRegexs(), hasSize(2));
        assertThat(context.getExcludedRegexs(), hasSize(2));
        assertThat(context.getIncludedRegexs(), hasItems(Pattern.quote(INCLUDE_REGEX_PATTERN.pattern()), Pattern.quote(INCLUDE_PARENT_URL) + ".*"));
        assertThat(context.getExcludedRegexs(), hasItems(Pattern.quote(EXCLUDE_REGEX_PATTERN.pattern()), Pattern.quote(EXCLUDE_PARENT_URL) + ".*"));
    }

    @Test
    public void testAuthentication() throws ProxyException, IOException {
        String contextName = TEST_CONTEXT_NAME + " - " + RandomStringUtils.randomAlphanumeric(3);
        zaproxy.createContext(contextName, true);
        String contextId = zaproxy.getContextInfo(contextName).getId();

        assertThat(zaproxy.getSupportedAuthenticationMethods(), hasSize(4));
        assertTrue(zaproxy.getSupportedAuthenticationMethods().containsAll(AuthenticationMethod.getValues()));

        assertTrue(StringUtils.isEmpty(zaproxy.getLoggedInIndicator(contextId)));
        assertTrue(StringUtils.isEmpty(zaproxy.getLoggedOutIndicator(contextId)));
        String logInIndicator = "<a href=\"logout.jsp\"></a>";
        String logOutIndicator = "/ui/login.jsp";
        zaproxy.setLoggedInIndicator(contextId, logInIndicator);
        zaproxy.setLoggedOutIndicator(contextId, logOutIndicator);
        assertTrue(StringUtils.isNotEmpty(zaproxy.getLoggedInIndicator(contextId)));
        assertTrue(StringUtils.isNotEmpty(zaproxy.getLoggedOutIndicator(contextId)));
        assertEquals(Pattern.quote(logInIndicator), zaproxy.getLoggedInIndicator(contextId));
        assertEquals(Pattern.quote(logOutIndicator), zaproxy.getLoggedOutIndicator(contextId));

        assertEquals(1, zaproxy.getAuthenticationMethodInfo(contextId).size());
        assertTrue(zaproxy.getAuthenticationMethodInfo(contextId).containsKey("methodName"));
        assertEquals(AuthenticationMethod.MANUAL_AUTHENTICATION.getValue(), zaproxy.getAuthenticationMethodInfo(contextId).get("methodName"));
        assertThat(zaproxy.getAuthMethodConfigParameters(AuthenticationMethod.MANUAL_AUTHENTICATION.getValue()), hasSize(0));
        List<Map<String, String>> formBasedAuthConfigParams = zaproxy.getAuthMethodConfigParameters(AuthenticationMethod.FORM_BASED_AUTHENTICATION.getValue());
        assertEquals(formBasedAuthConfigParams.size(), 2);
        for (Map<String, String> configParam : formBasedAuthConfigParams) {
            assertThat(configParam.keySet(), hasItems("name", "mandatory"));
            assertThat(configParam.values(), anyOf(hasItem("loginUrl"), hasItem("loginRequestData")));
        }

        String loginUrl = "http://localhost:8080/bodgeit/login.jsp";
        String loginRequestData = "username={%username%}&password={%password%}";
        zaproxy.setFormBasedAuthentication(contextId, loginUrl, loginRequestData);

        assertThat(zaproxy.getAuthenticationMethodInfo(contextId).keySet(), hasItems("methodName", "loginUrl", "loginRequestData"));
        assertEquals(loginUrl, zaproxy.getAuthenticationMethodInfo(contextId).get("loginUrl"));
        assertEquals(loginRequestData, zaproxy.getAuthenticationMethodInfo(contextId).get("loginRequestData"));

        List<User> users = zaproxy.getUsersList(contextId);
        assertTrue(users.size() == 0);
        String userName = "TestUser";
        String userId = zaproxy.newUser(contextId, userName);
        users = zaproxy.getUsersList(contextId);
        assertTrue(users.size() == 1);
        assertEquals(userId, users.get(0).getId());
        assertEquals(contextId, users.get(0).getContextId());
        assertEquals(userName, users.get(0).getName());
        assertEquals(false, users.get(0).isEnabled());
        assertEquals("UsernamePasswordAuthenticationCredentials", users.get(0).getCredentials().get("type"));

        User user = zaproxy.getUserById(contextId, userId);
        assertEquals(userId, user.getId());
        assertEquals(contextId, user.getContextId());
        assertEquals(userName, user.getName());
        assertEquals(false, user.isEnabled());
        assertEquals("UsernamePasswordAuthenticationCredentials", user.getCredentials().get("type"));

        List<Map<String, String>> authCredentialsConfigParams = zaproxy.getAuthenticationCredentialsConfigParams(contextId);
        assertTrue(authCredentialsConfigParams.size() == 2);

        Map<String, String> credentials = zaproxy.getAuthenticationCredentials(contextId, userId);
        assertEquals("UsernamePasswordAuthenticationCredentials", credentials.get("type"));
        assertEquals("null", credentials.get("username"));
        assertEquals("null", credentials.get("password"));

        String userNameParameter = "user1";
        String passwordParameter = "password1";
        String authCreds = "username=" + URLEncoder.encode(userNameParameter, "UTF-8") + "&password=" + URLEncoder.encode(passwordParameter, "UTF-8");
        zaproxy.setAuthenticationCredentials(contextId, userId, authCreds);
        credentials = zaproxy.getAuthenticationCredentials(contextId, userId);
        assertEquals("UsernamePasswordAuthenticationCredentials", credentials.get("type"));
        assertEquals(userNameParameter, credentials.get("username"));
        assertEquals(passwordParameter, credentials.get("password"));

        zaproxy.setUserEnabled(contextId, userId, true);
        user = zaproxy.getUserById(contextId, userId);
        assertEquals(true, user.isEnabled());

        String updatedUserName = "TestUser-Updated";
        zaproxy.setUserName(contextId, userId, updatedUserName);
        user = zaproxy.getUserById(contextId, userId);
        assertEquals(updatedUserName, user.getName());

        assertFalse(zaproxy.isForcedUserModeEnabled());
        assertThat(zaproxy.getForcedUserId(contextId), isEmptyOrNullString());
        zaproxy.setForcedUserModeEnabled(true);
        assertTrue(zaproxy.isForcedUserModeEnabled());
        zaproxy.setForcedUserModeEnabled(false);
        assertFalse(zaproxy.isForcedUserModeEnabled());
        zaproxy.setForcedUser(contextId, userId);
        assertEquals(userId, zaproxy.getForcedUserId(contextId));

        zaproxy.removeUser(contextId, userId);
        users = zaproxy.getUsersList(contextId);
        assertTrue(users.size() == 0);

        assertEquals("cookieBasedSessionManagement", zaproxy.getSessionManagementMethod(contextId));
        assertThat(zaproxy.getSupportedSessionManagementMethods(), hasItems("cookieBasedSessionManagement", "httpAuthSessionManagement"));
        zaproxy.setSessionManagementMethod(contextId, "httpAuthSessionManagement", null);
        assertEquals("httpAuthSessionManagement", zaproxy.getSessionManagementMethod(contextId));
    }

    @Test
    public void testAntiCsrfTokenMethods() throws ProxyException {
        List<String> antiCsrfTokens = zaproxy.getAntiCsrfTokenNames();
        String aCsrfTokenName = "secureToken";
        zaproxy.addAntiCsrfToken(aCsrfTokenName);
        assertEquals(antiCsrfTokens.size() + 1, zaproxy.getAntiCsrfTokenNames().size());
        assertThat(zaproxy.getAntiCsrfTokenNames(), hasItem(aCsrfTokenName));
        zaproxy.removeAntiCsrfToken(aCsrfTokenName);
        assertThat(zaproxy.getAntiCsrfTokenNames(), not(hasItem(aCsrfTokenName)));
    }

    @Test
    public void testGetXmlReport() throws ProxyException {
        String report = new String(zaproxy.getXmlReport());
        assert report.startsWith("<?xml version=\"1.0\"");
        assert report.endsWith("</OWASPZAPReport>");
    }

    @Test
    public void testGetHtmlReport() throws ProxyException {
        String report = new String(zaproxy.getHtmlReport()).trim();
        assert report.startsWith("<html>");
        assert report.endsWith("</html>");
    }

    @Test
    public void testGetHistory() throws ProxyException {
        driver.get(BASEURL);
        List<HarEntry> history = zaproxy.getHistory();
        assertThat(history.size(), greaterThan(0));
        assertEquals(history.get(0).getResponse().getStatus(), 302);
    }

    @Test
    public void testMakeRequest() throws IOException {
        driver.get(BASEURL + "task/search?q=test&search=Search");
        HarRequest origRequest = zaproxy.getHistory().get(0).getRequest();
        HarResponse origResponse = zaproxy.getHistory().get(0).getResponse();
        List<HarEntry> responses = zaproxy.makeRequest(origRequest, true);
        HarResponse manualResponse = responses.get(0).getResponse();

        assertEquals(origResponse.getBodySize(), manualResponse.getBodySize());
        assertEquals(origResponse.getContent().getText(), manualResponse.getContent().getText());
    }

    @Test
    public void testCookiesWithMakeRequest() throws IOException {
        System.out.println("Opening login page");
        openLoginPage();
        System.out.println("Logging on");

        login("bob", "password");        //sets a session ID cookie

        String sessionID = driver.manage().getCookieNamed("JSESSIONID").getValue();
        assert sessionID.length() > 4;
        System.out.println("getting history");
        List<HarEntry> history = zaproxy.getHistory();
        System.out.println("clearing history");
        zaproxy.clear();
        System.out.println("cleared");
        HarRequest copy = history.get(history.size() - 1).getRequest(); //The last request will contain a session ID
        copy = HarUtils.changeCookieValue(copy, "JSESSIONID", "nothing");

        List<HarEntry> responses = zaproxy.makeRequest(copy, true);
        //The changed session ID
        assertThat(responses.get(0).getRequest().getCookies().getCookies().get(0).getValue(), equalTo("nothing"));
    }

    @Test
    public void testSimpleActiveScanWorkflow() throws InterruptedException {
        zaproxy.setEnablePassiveScan(false);
        System.out.println("Opening login page");
        openLoginPage();
        System.out.println("Logging on");

        login("bob", "password");
        zaproxy.setEnableScanners("40018", true);
        zaproxy.deleteAlerts();
        zaproxy.scan(BASEURL);
        int scanId = zaproxy.getLastScannerScanId();
        int status = zaproxy.getScanProgress(scanId);
        while (status < 100) {
            Thread.sleep(2000);
            status = zaproxy.getScanProgress(scanId);
            System.out.println("Scan: "+status);
        }
        List<Alert> alerts = zaproxy.getAlerts();
        assertThat(alerts.size(), greaterThan(0));

        //Repeat after deleting alerts
        zaproxy.deleteAlerts();
        zaproxy.scan(BASEURL);
        scanId = zaproxy.getLastScannerScanId();
        status = zaproxy.getScanProgress(scanId);
        while (status < 100) {
            Thread.sleep(2000);
            status = zaproxy.getScanProgress(scanId);
            System.out.println("Scan: "+status);
        }
        List<Alert> secondBatchAlerts = zaproxy.getAlerts();
        assertThat(secondBatchAlerts.size(), greaterThan(0));
        assertThat(secondBatchAlerts.size(), equalTo(alerts.size()));
    }


    private Map<String, List<Alert>> getAlertsByHost(List<Alert> alerts) {

        Map<String, List<Alert>> alertsByHost = new HashMap<String, List<Alert>>();
        for (Alert alert : alerts) {
            URL url = null;
            try {
                url = new URL(alert.getUrl());
                String host = url.getHost();
                if (alertsByHost.get(host) == null) {
                    alertsByHost.put(host, new ArrayList<Alert>());
                }
                alertsByHost.get(host).add(alert);
            } catch (MalformedURLException e) {
                System.err.println("Skipping malformed URL: "+alert.getUrl());
                e.printStackTrace();
            }
        }
        return alertsByHost;
    }


    public void openLoginPage() {
        driver.get(BASEURL + "user/login");
    }

    public void login(String user, String pass) {
        driver.findElement(By.id("username")).clear();
        driver.findElement(By.id("username")).sendKeys(user);
        driver.findElement(By.id("password")).clear();
        driver.findElement(By.id("password")).sendKeys(pass);
        driver.findElement(By.name("_action_login")).click();
    }

}
