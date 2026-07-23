package com.loganalytics.controller;

import com.loganalytics.dto.ApiResponse;
import com.loganalytics.dto.RegisterRequest;
import com.loganalytics.service.ActivityLogger;
import com.loganalytics.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final ActivityLogger activityLogger;

    public AuthController(UserService userService,
                          ActivityLogger activityLogger) {

        this.userService = userService;
        this.activityLogger = activityLogger;
    }

    @PostMapping("/register")
    // FIX: register.html sends JSON (Content-Type: application/json), but this
    // parameter had no @RequestBody, so Spring tried to bind it as regular form
    // params instead — username/password/role all came through as null and
    // registration silently failed every time.
    public ApiResponse register(@RequestBody RegisterRequest req,
                                HttpServletRequest http) {

        String ip = http.getRemoteAddr();

        boolean ok = userService.register(
                req.getUsername(),
                req.getPassword(),
                req.getRole()
        );

        activityLogger.log(
                ip,
                "POST",
                "/register",
                ok ? 200 : 400,
                ok ? "Registration successful"
                        : "Registration failed"
        );

        return new ApiResponse(
                ok,
                ok ? "Registration successful"
                        : "Username already exists"
        );
    }
}