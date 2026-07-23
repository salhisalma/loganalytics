package com.loganalytics.repository;

import com.loganalytics.model.ThreatAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ThreatAlertRepository extends JpaRepository<ThreatAlert, Long> {
    List<ThreatAlert> findTop50ByOrderByDetectedAtDesc();
    long countByThreatType(String threatType);
    long countBySeverity(String severity);

    // NEW: needed for the "Active Threats" stat and the Resolve workflow
    long countByResolvedFalse();
    long countBySeverityAndResolvedFalse(String severity);
    List<ThreatAlert> findByResolvedFalseOrderByDetectedAtDesc();
}