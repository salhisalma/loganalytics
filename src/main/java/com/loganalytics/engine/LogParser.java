package com.loganalytics.engine;

import com.loganalytics.model.LogEntry;
import org.springframework.stereotype.Component;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class LogParser {
    // FIX: was "([\\d.]+)" which only matches IPv4 (digits + dots).
    // On Windows, http.getRemoteAddr() for localhost often returns the IPv6
    // loopback address "0:0:0:0:0:0:0:1", which contains colons and was being
    // silently rejected by this regex — parse() returned null for every line,
    // so nothing ever reached the database. "\\S+" matches any non-whitespace
    // token, so it now accepts IPv4, IPv6, and IPv6 shorthand (::1) alike.
    private static final Pattern LOG_PATTERN = Pattern.compile(
        "(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\s+(\\w+)\\s+" +
        "IP=(\\S+)\\s+\\|\\s+METHOD=(\\w+)\\s+\\|\\s+URL=([^|]+)\\s+\\|\\s+" +
        "STATUS=(\\d+)\\s+\\|\\s+MSG=(.*)"
    );
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public LogEntry parse(String line) {
        Matcher m = LOG_PATTERN.matcher(line);
        if (!m.matches()) return null;
        LogEntry entry = new LogEntry();
        entry.setTimestamp(LocalDateTime.parse(m.group(1), DATE_FORMATTER));
        entry.setSeverity(m.group(2));
        entry.setIpAddress(m.group(3));
        entry.setHttpMethod(m.group(4));
        entry.setRequestUrl(m.group(5));
        entry.setStatusCode(Integer.parseInt(m.group(6)));
        entry.setRawLine(line);
        return entry;
    }
}