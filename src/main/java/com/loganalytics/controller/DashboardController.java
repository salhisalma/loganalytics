package com.loganalytics.controller;

import com.loganalytics.dto.ApiResponse;
import com.loganalytics.model.LogEntry;
import com.loganalytics.model.ThreatAlert;
import com.loganalytics.service.LogService;
import com.loganalytics.service.ThreatAlertService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {
    private final LogService logService;
    private final ThreatAlertService alertService;

    public DashboardController(LogService logService, ThreatAlertService alertService) {
        this.logService = logService;
        this.alertService = alertService;
    }

    @GetMapping("/logs")
    public List<LogEntry> logs() { return logService.recent(); }

    @GetMapping("/alerts")
    public List<ThreatAlert> alerts() { return alertService.recent(); }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalLogs", logService.total());
        stats.put("failedRequests", logService.failedRequests());
        stats.put("totalAlerts", alertService.total());
        stats.put("highAlerts", alertService.countBySeverity("HIGH"));
        stats.put("criticalAlerts", alertService.countBySeverity("CRITICAL"));
        stats.put("mediumAlerts", alertService.countBySeverity("MEDIUM"));
        stats.put("lowAlerts", alertService.countBySeverity("LOW"));

        // NEW: fields needed for the "SOC-style" dashboard (matches the mock-up cards)
        stats.put("activeThreats", alertService.countActive());
        stats.put("logsLastHour", logService.countSince(LocalDateTime.now().minusHours(1)));
        stats.put("logsLast24h", logService.countSince(LocalDateTime.now().minusHours(24)));

        return stats;
    }

    // NEW: marks an alert as resolved — called by the "Resolve" button on the dashboard
    @PutMapping("/alerts/{id}/resolve")
    public ResponseEntity<ApiResponse> resolveAlert(@PathVariable Long id) {
        Optional<ThreatAlert> resolved = alertService.resolve(id);
        if (resolved.isPresent()) {
            return ResponseEntity.ok(new ApiResponse(true, "Alert #" + id + " marked as resolved"));
        }
        return ResponseEntity.status(404).body(new ApiResponse(false, "Alert #" + id + " not found"));
    }
}