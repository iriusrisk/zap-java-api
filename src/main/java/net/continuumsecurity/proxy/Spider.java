package net.continuumsecurity.proxy;

import java.util.List;

public interface Spider {
    public void spider(String url);
    public int getSpiderStatus();
    public List<String> getSpiderResults();
    public void excludeFromSpider(String regex);
    public void setMaxDepth(int depth);
    public void setPostForms(boolean post);
    public void setThreadCount(int threads);

}
