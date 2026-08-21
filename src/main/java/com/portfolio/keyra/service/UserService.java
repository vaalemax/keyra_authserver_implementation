package com.portfolio.keyra.service;

import com.portfolio.keyra.model.User;
import com.portfolio.keyra.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional
    public void enableTwoFactor(User user, String secret, List<String> backupCodes) {

        user.setTwoFactorEnabled(true);
        user.setTwoFactorSecret(secret);

        try {
            ObjectMapper mapper = new ObjectMapper();
            String backupCodesJson = mapper.writeValueAsString(backupCodes);
            user.setBackupCodes(backupCodesJson);
        } catch (Exception e) {
            log.error("Error storing backup codes", e);
            throw new RuntimeException("Error storing backup codes", e);
        }

        userRepository.save(user);
        log.info("2FA enabled successfully for user: {}", user.getUsername());
    }

    @Transactional
    public void disableTwoFactor(User user) {
        log.info("Disabling 2FA for user: {}", user.getUsername());

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        user.setBackupCodes(null);

        userRepository.save(user);
        log.info("2FA disabled successfully for user: {}", user.getUsername());
    }

    public List<String> getBackupCodes(User user) {
        if (user.getBackupCodes() == null) {
            return new ArrayList<>();
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(user.getBackupCodes(),
                    mapper.getTypeFactory().constructCollectionType(
                            List.class, String.class));
        } catch (Exception e) {
            log.error("Error reading backup codes", e);
            return new ArrayList<>();
        }
    }

    @Transactional
    public void updateBackupCodes(User user, List<String> updatedCodes) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String backupCodesJson = mapper.writeValueAsString(updatedCodes);
            user.setBackupCodes(backupCodesJson);
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("Error updating backup codes", e);
        }
    }
}
