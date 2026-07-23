package com.loganalytics.engine;

import com.loganalytics.model.LogEntry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LogParserTest {

    private final LogParser parser = new LogParser();

    @Test
    void parserExtractsAllFieldsCorrectly() {
        String line = "2026-07-14 10:42:07 INFO IP=10.0.0.5 | METHOD=POST | URL=/login | STATUS=401 | MSG=failed login for user=bob";

        LogEntry entry = parser.parse(line);

        assertNotNull(entry);
        assertEquals("10.0.0.5", entry.getIpAddress());
        assertEquals("POST", entry.getHttpMethod());
        assertEquals("/login", entry.getRequestUrl());
        assertEquals(401, entry.getStatusCode());
        assertEquals("INFO", entry.getSeverity());
        assertNotNull(entry.getTimestamp());
        assertEquals(2026, entry.getTimestamp().getYear());
    }

    @Test
    void parserHandlesSqlInjectionPayloadInUrl() {
        String line = "2026-07-14 10:45:00 INFO IP=192.168.1.10 | METHOD=GET | URL=/products?id=1' OR 1=1 -- | STATUS=200 | MSG=suspicious query string";

        LogEntry entry = parser.parse(line);

        assertNotNull(entry);
        assertTrue(entry.getRequestUrl().contains("OR 1=1"));
        assertEquals(200, entry.getStatusCode());
    }

    @Test
    void parserReturnsNullForMalformedLine() {
        String line = "this is not a valid log line at all";

        LogEntry entry = parser.parse(line);

        assertNull(entry);
    }

    @Test
    void parserReturnsNullWhenFieldsAreMissing() {
        // missing STATUS and MSG fields
        String line = "2026-07-14 10:42:07 INFO IP=10.0.0.5 | METHOD=POST | URL=/login";

        LogEntry entry = parser.parse(line);

        assertNull(entry);
    }

    @Test
    void parserPreservesRawLine() {
        String line = "2026-07-14 10:42:07 INFO IP=10.0.0.5 | METHOD=GET | URL=/dashboard | STATUS=200 | MSG=ok";

        LogEntry entry = parser.parse(line);

        assertNotNull(entry);
        assertEquals(line, entry.getRawLine());
    }

    @Test
    void parserAcceptsIPv6Addresses() {
        // Regression test: Windows' localhost often resolves to the IPv6 loopback
        // form "0:0:0:0:0:0:0:1" instead of "127.0.0.1". The parser must not
        // silently drop these lines.
        String line = "2026-07-14 10:42:07 INFO IP=0:0:0:0:0:0:0:1 | METHOD=POST | URL=/login | STATUS=401 | MSG=failed login for user=admin";

        LogEntry entry = parser.parse(line);

        assertNotNull(entry);
        assertEquals("0:0:0:0:0:0:0:1", entry.getIpAddress());
    }
}