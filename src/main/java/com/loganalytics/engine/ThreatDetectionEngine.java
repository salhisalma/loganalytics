package com.loganalytics.engine;

import com.loganalytics.model.LogEntry;
import com.loganalytics.service.ThreatAlertService;
import org.springframework.stereotype.Component;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ThreatDetectionEngine {

    private final ThreatAlertService alertService;

    // --- state for brute force ---
    private final Map<String, Integer> failedLogins = new ConcurrentHashMap<>();

    // --- state for request flood ---
    private final Map<String, Deque<Long>> requestTimes = new ConcurrentHashMap<>();

    // --- state for repeated failed access (NEW) ---
    private final Map<String, Deque<Long>> failedRequestTimes = new ConcurrentHashMap<>();

    private static final int BRUTE_FORCE_THRESHOLD = 5;
    private static final int FLOOD_THRESHOLD = 20;
    private static final long FLOOD_WINDOW_MS = 10_000;

    // NEW: repeated failed access (non-2xx) from a single IP
    private static final int FAILED_ACCESS_THRESHOLD = 10;
    private static final long FAILED_ACCESS_WINDOW_MS = 60_000;

    private static final List<String> SQLI_PATTERNS = Arrays.asList(
            "or 1=1", "union select", "drop table", "--", "1=1", "' or '1'='1", "or 1=1=1");

    private static final List<String> SUSPICIOUS_PATTERNS = Arrays.asList(
            "..", "/etc/passwd", "script", ".php", ".asp", ".jsp");

    public ThreatDetectionEngine(ThreatAlertService alertService) {
        this.alertService = alertService;
    }

    public void analyze(LogEntry entry) {
        checkBruteForce(entry);
        checkSqlInjection(entry);
        checkSuspiciousUrl(entry);
        checkFlood(entry);
        checkRepeatedFailedAccess(entry); 
    }

    private void checkBruteForce(LogEntry entry) {
        boolean failedLogin = entry.getRequestUrl().contains("/login") && entry.getStatusCode() == 401;
        if (failedLogin) {
            int count = failedLogins.merge(entry.getIpAddress(), 1, Integer::sum);
            if (count >= BRUTE_FORCE_THRESHOLD) {
                alertService.raise("BRUTE_FORCE", entry.getIpAddress(), "HIGH",
                        count + " failed logins from " + entry.getIpAddress());
                failedLogins.put(entry.getIpAddress(), 0);
            }
        } else if (entry.getRequestUrl().contains("/login") && entry.getStatusCode() == 200) {
            failedLogins.remove(entry.getIpAddress());
        }
    }

    private void checkSqlInjection(LogEntry entry) {
        String url = entry.getRequestUrl().toLowerCase();
        for (String pattern : SQLI_PATTERNS) {
            if (url.contains(pattern)) {
                alertService.raise("SQL_INJECTION", entry.getIpAddress(), "CRITICAL",
                        "SQLi pattern '" + pattern + "' in URL: " + entry.getRequestUrl());
                break;
            }
        }
    }

    private void checkSuspiciousUrl(LogEntry entry) {
        String url = entry.getRequestUrl().toLowerCase();
        for (String pattern : SUSPICIOUS_PATTERNS) {
            if (url.contains(pattern)) {
                alertService.raise("SUSPICIOUS_URL", entry.getIpAddress(), "MEDIUM",
                        "Abnormal endpoint access: " + entry.getRequestUrl());
                break;
            }
        }
    }

    private void checkFlood(LogEntry entry) {
        long now = System.currentTimeMillis();
        Deque<Long> times = requestTimes.computeIfAbsent(entry.getIpAddress(), k -> new ArrayDeque<>());
        times.addLast(now);
        while (!times.isEmpty() && now - times.peekFirst() > FLOOD_WINDOW_MS) times.pollFirst();
        if (times.size() >= FLOOD_THRESHOLD) {
            alertService.raise("REQUEST_FLOOD", entry.getIpAddress(), "MEDIUM",
                    times.size() + " requests in 10s from " + entry.getIpAddress());
            times.clear();
        }
    }

    /**
     * NEW RULE — Repeated failed access.
     * Flags an IP that racks up many non-2xx responses (403, 404, 500, etc.)
     * within a rolling window — e.g. scanning for hidden endpoints or
     * probing for misconfigured resources.
     */
    private void checkRepeatedFailedAccess(LogEntry entry) {
        int status = entry.getStatusCode();
        boolean isFailure = status < 200 || status >= 300;
        if (!isFailure) return;

        long now = System.currentTimeMillis();
        Deque<Long> times = failedRequestTimes.computeIfAbsent(entry.getIpAddress(), k -> new ArrayDeque<>());
        times.addLast(now);
        while (!times.isEmpty() && now - times.peekFirst() > FAILED_ACCESS_WINDOW_MS) times.pollFirst();

        if (times.size() >= FAILED_ACCESS_THRESHOLD) {
            alertService.raise("REPEATED_FAILED_ACCESS", entry.getIpAddress(), "MEDIUM",
                    times.size() + " non-2xx responses in 60s from " + entry.getIpAddress());
            times.clear();
        }
    }
}