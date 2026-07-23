package com.loganalytics.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDateTime;

@Entity
@Table(name = "log_entries")
@Getter
@Setter
public class LogEntry {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    private LocalDateTime timestamp;
    @Column(nullable = false)
    private String ipAddress;
    @Column(nullable = false)
    private String requestUrl;
    @Column(nullable = false)
    private String httpMethod;
    @Column(nullable = false)
    private int statusCode;
    @Column(nullable = false)
    private String severity;
    @Column(length = 2000)
    private String rawLine;
    public LogEntry() {}
}
