package com.loganalytics.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

@Service
public class ActivityLogger {
    private static final Logger log = LogManager.getLogger("com.loganalytics");
    public void log(String ip, String method, String url, int status, String msg) {
        log.info("IP={} | METHOD={} | URL={} | STATUS={} | MSG={}", ip, method, url, status, msg);
    }
}
