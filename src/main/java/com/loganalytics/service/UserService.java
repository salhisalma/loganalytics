package com.loganalytics.service;

import com.loganalytics.model.AppUser;
import com.loganalytics.repository.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final AppUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    public UserService(AppUserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    public boolean register(String username, String password, String role) {
        if (userRepository.existsByUsername(username)) return false;
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role != null ? role : "ROLE_USER");
        userRepository.save(user);
        return true;
    }
    public boolean check(String username, String password) {
        return userRepository.findByUsername(username)
                .map(user -> passwordEncoder.matches(password, user.getPassword()))
                .orElse(false);
    }
    public AppUser findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }
}
