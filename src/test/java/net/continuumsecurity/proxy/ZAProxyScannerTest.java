package net.continuumsecurity.proxy;


import edu.umass.cs.benchlab.har.HarEntry;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.webbitserver.helpers.Base64;

import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.thoughtworks.selenium.SeleneseTestBase.assertEquals;
import static org.junit.Assert.assertTrue;

public class ZAProxyScannerTest {
    static WebDriver driver;
    static ZAProxyScanner zaproxy;
    static String HOST = "127.0.0.1";
    static int PORT = 8888;
    static String CHROME = "src/test/resources/chromedriver";
    static String GOOGLE = "http://www.google.com";

    @BeforeClass
    public static void configure() throws ProxyException, UnknownHostException {
        zaproxy = new ZAProxyScanner(HOST,PORT);
        DesiredCapabilities capabilities = new DesiredCapabilities();
        capabilities.setCapability(CapabilityType.PROXY,zaproxy.getSeleniumProxy());

        System.setProperty("webdriver.chrome.driver", CHROME);
        driver = new ChromeDriver(capabilities);
        driver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
    }

    @AfterClass
    public static void teardown() {
        driver.close();
    }

    @Before
    public void setup() throws ProxyException {
        zaproxy.clear();
        driver.manage().deleteAllCookies();
    }

    @Test
    public void testGetHistory() throws ProxyException {
        driver.get(GOOGLE);
        List<HarEntry> history = zaproxy.getHistory();
        assertTrue(history.size() > 1); //should redirect to https
        assertTrue(history.get(history.size() - 1).getRequest().getUrl().startsWith("https"));
    }

    @Test
    public void testFindInRequestHistory() throws ProxyException {
        driver.get(GOOGLE);
        WebElement element = driver.findElement(By.name("q"));
        element.sendKeys("continuumsecurity");
        element.submit();

        try {
            Thread.sleep(4000);
        } catch (InterruptedException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

        List<HarEntry> hist = zaproxy.findInRequestHistory("continuumsecurity");
        System.out.println(hist.get(0).getRequest().toString());
        System.out.println(hist.get(1).getRequest().toString());

        assertEquals(1,hist.size());
        assertTrue(hist.get(0).getRequest().getMethod().equals("GET"));
        assertTrue(hist.get(0).getRequest().getQueryString().toString().contains("q"));
        assertTrue(hist.get(0).getRequest().getQueryString().toString().contains("continuumsecurity"));
        assertEquals("HTTP/1.1", hist.get(0).getRequest().getHttpVersion());
        assertEquals(200, hist.get(0).getResponse().getStatus());
        String content = new String(Base64.decode(hist.get(0).getResponse().getContent().getText()));
        System.out.println(content);
        assertTrue(content.contains("continuum security"));
    }
}
