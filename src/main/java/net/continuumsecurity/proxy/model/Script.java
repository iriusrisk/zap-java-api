package net.continuumsecurity.proxy.model;

import org.zaproxy.clientapi.core.ApiResponseSet;

/**
 * Copyright VMware, Inc. All rights reserved. -- VMware Confidential
 */
public class Script {
    String name;
    String type;
    String engine;
    boolean error;
    String description;

    public Script(ApiResponseSet apiResponseSet) {
        name = apiResponseSet.getAttribute("name");
        type = apiResponseSet.getAttribute("type");
        engine = apiResponseSet.getAttribute("engine");
        error = Boolean.valueOf(apiResponseSet.getAttribute("error"));
        description = apiResponseSet.getAttribute("description");
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getEngine() {
        return engine;
    }

    public void setEngine(String engine) {
        this.engine = engine;
    }

    public boolean isError() {
        return error;
    }

    public void setError(boolean error) {
        this.error = error;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
