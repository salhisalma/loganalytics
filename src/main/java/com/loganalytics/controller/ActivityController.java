package com.loganalytics.controller;

import com.loganalytics.dto.ApiResponse;
import com.loganalytics.service.ActivityLogger;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/activity")
public class ActivityController {

    private final ActivityLogger activityLogger;

    public ActivityController(ActivityLogger activityLogger) {
        this.activityLogger = activityLogger;
    }

    @PostMapping("/simulate/bruteforce")
    public ApiResponse bruteForce(HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        for (int i = 0; i < 6; i++) {
            activityLogger.log(ip, "POST", "/login", 401, "failed login for user=admin");
        }
        return new ApiResponse(true, "Simulated brute force from " + ip);
    }

    @PostMapping("/simulate/sqli")
    public ApiResponse sqlInjection(HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        activityLogger.log(ip, "GET", "/products?id=1' OR '1'='1", 200, "suspicious query string");
        return new ApiResponse(true, "Simulated SQL injection attempt");
    }

    @PostMapping("/simulate/flood")
    public ApiResponse flood(HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        for (int i = 0; i < 25; i++) {
            activityLogger.log(ip, "GET", "/api/data", 200, "normal request " + i);
        }
        return new ApiResponse(true, "Simulated request flood from " + ip);
    }

    @PostMapping("/simulate/suspicious")
    public ApiResponse suspicious(HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        activityLogger.log(ip, "GET", "/../../etc/passwd", 404, "path traversal attempt");
        return new ApiResponse(true, "Simulated suspicious URL access");
    }

    // NEW: triggers the REPEATED_FAILED_ACCESS rule (many non-2xx responses from one IP)
    @PostMapping("/simulate/failedaccess")
    public ApiResponse repeatedFailedAccess(HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        for (int i = 0; i < 12; i++) {
            activityLogger.log(ip, "GET", "/api/secret-resource-" + i, 403, "forbidden access attempt");
        }
        return new ApiResponse(true, "Simulated repeated failed access from " + ip);
    }
}