package com.loganalytics.service;

import com.loganalytics.model.ThreatAlert;
import com.loganalytics.repository.ThreatAlertRepository;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class ThreatAlertService {
    private final ThreatAlertRepository alertRepository;

    public ThreatAlertService(ThreatAlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    public void raise(String type, String ip, String severity, String description) {
        ThreatAlert alert = new ThreatAlert();
        alert.setThreatType(type);
        alert.setSourceIp(ip);
        alert.setSeverity(severity);
        alert.setDescription(description);
        alert.setDetectedAt(LocalDateTime.now());
        alertRepository.save(alert);
    }

    public List<ThreatAlert> recent() { return alertRepository.findTop50ByOrderByDetectedAtDesc(); }
    public long countByType(String type) { return alertRepository.countByThreatType(type); }
    public long countBySeverity(String severity) { return alertRepository.countBySeverity(severity); }
    public long total() { return alertRepository.count(); }

    // NEW: powers the "Active Threats" card and the filter tabs
    public long countActive() { return alertRepository.countByResolvedFalse(); }
    public long countActiveCritical() { return alertRepository.countBySeverityAndResolvedFalse("CRITICAL"); }

    // NEW: marks an alert as resolved (used by the "Resolve" button)
    public Optional<ThreatAlert> resolve(Long id) {
        Optional<ThreatAlert> found = alertRepository.findById(id);
        found.ifPresent(alert -> {
            alert.setResolved(true);
            alertRepository.save(alert);
        });
        return found;
    }
}