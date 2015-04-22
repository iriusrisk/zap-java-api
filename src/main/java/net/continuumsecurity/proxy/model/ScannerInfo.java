package net.continuumsecurity.proxy.model;

import org.zaproxy.clientapi.core.ApiResponseSet;

/**
 * Created by stephen on 20/04/15.
 */
public class ScannerInfo {
    boolean enabled;
    int wascId;
    int cweId;

    public ScannerInfo(ApiResponseSet responseSet) {
        enabled = Boolean.parseBoolean(responseSet.getAttribute("enabled"));
        wascId = Integer.parseInt(responseSet.getAttribute("wascid"));
        cweId = Integer.parseInt(responseSet.getAttribute("cweid"));
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getWascId() {
        return wascId;
    }

    public int getCweId() {
        return cweId;
    }
}
