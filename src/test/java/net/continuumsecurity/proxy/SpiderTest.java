package net.continuumsecurity.proxy;

import org.junit.BeforeClass;
import org.junit.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class SpiderTest {
    static ZAProxyScanner zaproxy;
    static String HOST = "127.0.0.1";
    static int PORT = 8888;
    static String BASEURL = "http://testphp.vulnweb.com";
    static String DEFAULT_CONTEXT = "Default Context";

    @BeforeClass
    public static void configure() throws Exception {
        zaproxy = new ZAProxyScanner(HOST, PORT, "apisecret");
    }


    @Test
    public void testSpider() {
        zaproxy.setIncludeInContext(DEFAULT_CONTEXT, BASEURL.concat(".*"));
        zaproxy.spider(BASEURL, true, DEFAULT_CONTEXT);
        int progress = 0;
        while (progress < 100) {
            progress = zaproxy.getSpiderProgress(zaproxy.getLastSpiderScanId());
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }
        List<String> results = zaproxy.getSpiderResults(zaproxy.getLastSpiderScanId());

        assertThat(results.size(),equalTo(63));
        assert results.contains(BASEURL);
        for (String url : results) {
           System.out.println(url);
        }
    }
}
