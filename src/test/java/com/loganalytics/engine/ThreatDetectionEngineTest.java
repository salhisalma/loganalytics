package com.loganalytics.engine;

import com.loganalytics.model.LogEntry;
import com.loganalytics.service.ThreatAlertService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ThreatDetectionEngineTest {

    @Mock
    private ThreatAlertService alertService;

    @InjectMocks
    private ThreatDetectionEngine engine;

    private LogEntry entryFor(String ip, String url, int status) {
        LogEntry e = new LogEntry();
        e.setIpAddress(ip);
        e.setRequestUrl(url);
        e.setStatusCode(status);
        e.setHttpMethod("GET");
        e.setSeverity("INFO");
        return e;
    }

    @Test
    void fiveFailedLoginsRaiseBruteForceAlert() {
        for (int i = 0; i < 5; i++) {
            engine.analyze(entryFor("10.0.0.1", "/login", 401));
        }

        verify(alertService, atLeastOnce())
                .raise(eq("BRUTE_FORCE"), eq("10.0.0.1"), eq("HIGH"), anyString());
    }

    @Test
    void fourFailedLoginsDoNotRaiseBruteForceAlert() {
        for (int i = 0; i < 4; i++) {
            engine.analyze(entryFor("10.0.0.2", "/login", 401));
        }

        verify(alertService, never())
                .raise(eq("BRUTE_FORCE"), anyString(), anyString(), anyString());
    }

    @Test
    void successfulLoginResetsFailedLoginCounter() {
        for (int i = 0; i < 4; i++) {
            engine.analyze(entryFor("10.0.0.3", "/login", 401));
        }
        engine.analyze(entryFor("10.0.0.3", "/login", 200)); // reset
        engine.analyze(entryFor("10.0.0.3", "/login", 401)); // only 1 after reset

        verify(alertService, never())
                .raise(eq("BRUTE_FORCE"), anyString(), anyString(), anyString());
    }

    @Test
    void sqlInjectionPayloadRaisesCriticalAlert() {
        engine.analyze(entryFor("192.168.1.10", "/products?id=1' OR 1=1 --", 200));

        verify(alertService).raise(eq("SQL_INJECTION"), eq("192.168.1.10"), eq("CRITICAL"), anyString());
    }

    @Test
    void normalUrlDoesNotRaiseSqlInjectionAlert() {
        engine.analyze(entryFor("192.168.1.11", "/dashboard", 200));

        verify(alertService, never())
                .raise(eq("SQL_INJECTION"), anyString(), anyString(), anyString());
    }

    @Test
    void pathTraversalRaisesSuspiciousUrlAlert() {
        engine.analyze(entryFor("192.168.1.12", "/../../etc/passwd", 404));

        verify(alertService).raise(eq("SUSPICIOUS_URL"), eq("192.168.1.12"), eq("MEDIUM"), anyString());
    }

    @Test
    void twentyRequestsInWindowRaiseFloodAlert() {
        for (int i = 0; i < 20; i++) {
            engine.analyze(entryFor("172.16.0.5", "/api/data", 200));
        }

        verify(alertService).raise(eq("REQUEST_FLOOD"), eq("172.16.0.5"), eq("MEDIUM"), anyString());
    }

    @Test
    void tenNon2xxResponsesRaiseRepeatedFailedAccessAlert() {
        for (int i = 0; i < 10; i++) {
            engine.analyze(entryFor("172.16.0.9", "/api/secret-" + i, 403));
        }

        verify(alertService).raise(eq("REPEATED_FAILED_ACCESS"), eq("172.16.0.9"), eq("MEDIUM"), anyString());
    }

    @Test
    void successfulResponsesDoNotTriggerRepeatedFailedAccess() {
        for (int i = 0; i < 15; i++) {
            engine.analyze(entryFor("172.16.0.10", "/api/data-" + i, 200));
        }

        verify(alertService, never())
                .raise(eq("REPEATED_FAILED_ACCESS"), anyString(), anyString(), anyString());
    }
}