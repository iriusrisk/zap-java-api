package net.continuumsecurity.proxy;

import org.junit.Test;

public class TestHarUtils {

    @Test
    public void testCookieReplaceRegex() {
        String[] headers = new String[3];
        headers[0] = "JSESSIONID=4D815DF50A74E9C456A1FB5CFD9B0A3D";
        headers[1] = "JSESSIONID=one; A=b";
        headers[2] = "OTHERJSESSIONID=two; JSESSIONID=one; A=b";

        String name="JSESSIONID";
        String value="shazam";
        //String pattern = "([; ]"+name+")=[\\\\S]*?([\\\\s;]].*)";
        String patternMulti = "([; ]"+name+")=[^;]*(.*)";
        String patternStart = "^("+name+")=[^;]*(.*)";

        for (String header : headers) {
            System.out.println("Header: "+header);
            String updated = header.replaceAll(patternMulti, "$1="+value+"$2");
            if (updated.equals(header)) {
                updated = header.replaceAll(patternStart, "$1="+value+"$2");
            }
            System.out.println("UPDATED: "+updated);
        }

    }
}
