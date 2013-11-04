package net.continuumsecurity.proxy;


import edu.umass.cs.benchlab.har.HarEntry;
import edu.umass.cs.benchlab.har.HarRequest;
import edu.umass.cs.benchlab.har.HarResponse;
import org.junit.*;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertTrue;

public class ZAProxyScannerTest {
    static WebDriver driver;
    static ZAProxyScanner zaproxy;
    static String HOST = "127.0.0.1";
    static int PORT = 8888;
    static String CHROME = "src/test/resources/chromedriver";
    static String BASEURL = "http://localhost:8080/ropeytasks-0.1/";

    @BeforeClass
    public static void configure() throws Exception {
        zaproxy = new ZAProxyScanner(HOST, PORT);
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
    public void testGetHistory() throws ProxyException {
        driver.get(BASEURL);
        List<HarEntry> history = zaproxy.getHistory();
        assertTrue(history.size() > 1); //should redirect to login
        Assert.assertEquals(history.get(0).getResponse().getStatus(),302);
    }

    @Test
    public void testMakeRequest() throws IOException {
        driver.get(BASEURL+"task/search?q=test&search=Search");
        HarRequest origRequest = zaproxy.getHistory().get(0).getRequest();
        HarResponse origResponse = zaproxy.getHistory().get(0).getResponse();
        List<HarEntry> responses = zaproxy.makeRequest(origRequest, true);
        HarResponse manualResponse = responses.get(0).getResponse();

        Assert.assertEquals(origResponse.getBodySize(),manualResponse.getBodySize());
        Assert.assertEquals(origResponse.getContent().getText(),manualResponse.getContent().getText());
    }
}
