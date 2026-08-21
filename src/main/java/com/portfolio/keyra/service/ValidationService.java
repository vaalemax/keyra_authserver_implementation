package com.portfolio.keyra.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ValidationService {

    private static final Logger log = LoggerFactory.getLogger(ValidationService.class);

    public boolean isPasswordSecure(String password) {
        boolean isSecure = password != null && password.length() >= 12;

        log.trace("Password security check: {} (length: {})",
                isSecure ? "SECURE" : "WEAK",
                password != null ? password.length() : 0);

        return isSecure;
    }

    public void validateCredentialPassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }
        validatePasswordComplexity(password);
    }

    public void validateCredentialPasswordIfPresent(String password) {
        if (password == null || password.trim().isEmpty()) {
            return;
        }
        validatePasswordComplexity(password);
    }

    private void validatePasswordComplexity(String password) {
        if (password.length() < 8)
            throw new IllegalArgumentException("Password must be at least 8 characters");

        if (password.length() > 256)
            throw new IllegalArgumentException("Password must not exceed 256 characters");
    }
}