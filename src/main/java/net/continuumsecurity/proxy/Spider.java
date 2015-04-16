package net.continuumsecurity.proxy;

import java.util.List;

public interface Spider {
    public void spider(String url);
    public int getSpiderProgress(int scanId);
    public int getLastSpiderScanId();
    public List<String> getSpiderResults(int scanId);
    public void excludeFromSpider(String regex);
    public void setMaxDepth(int depth);
    public void setPostForms(boolean post);
    public void setThreadCount(int threads);

}
