package com.loganalytics.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDateTime;

@Entity
@Table(name = "threat_alerts")
@Getter
@Setter
public class ThreatAlert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    private LocalDateTime detectedAt;
    @Column(nullable = false)
    private String threatType;
    @Column(nullable = false)
    private String sourceIp;
    @Column(nullable = false)
    private String description;
    @Column(nullable = false)
    private String severity;

    // NEW: tracks whether an analyst has resolved this alert (drives the "Resolve" button
    // and the Active Threats stat on the dashboard)
    @Column(nullable = false)
    private boolean resolved = false;

    public ThreatAlert() {}
}