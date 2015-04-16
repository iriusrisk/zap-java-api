package net.continuumsecurity.proxy;

import org.junit.BeforeClass;
import org.junit.Test;

import java.util.List;

public class SpiderTest {
    static ZAProxyScanner zaproxy;
    static String HOST = "127.0.0.1";
    static int PORT = 8888;
    static String BASEURL = "http://localhost:9110/ropeytasks/user/login";

    @BeforeClass
    public static void configure() throws Exception {
        zaproxy = new ZAProxyScanner(HOST, PORT,"");
    }

    @Test
    public void testSpider() {
        zaproxy.spider(BASEURL);
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

        assert 2 == results.size();
        assert results.contains(BASEURL);
        for (String url : results) {
           System.out.println(url);
        }
    }
}
