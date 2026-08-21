package com.portfolio.keyra.service;

import com.portfolio.keyra.model.User;
import com.portfolio.keyra.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.*;

@Service
@RequiredArgsConstructor
public class KeyraOidcUserService extends OidcUserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
        OidcUser oidcUser = super.loadUser(userRequest);

        String username = oidcUser.getSubject();

        userRepository.findByUsername(username)
                .orElseGet(() -> provisionUser(username));

        Set<GrantedAuthority> authorities =
                new HashSet<>(oidcUser.getAuthorities());

        List<String> roles = oidcUser.getClaimAsStringList("roles");

        if (roles != null) {
            roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .forEach(authorities::add);
        }

        return new DefaultOidcUser(
                authorities,
                oidcUser.getIdToken(),
                oidcUser.getUserInfo()
        );
    }

    private User provisionUser(String username) {
        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(UUID.randomUUID().toString()));
        user.setEncryptionKey(generateRandomAesKeyBase64());
        user.setTwoFactorEnabled(false);
        return userRepository.save(user);
    }

    private String generateRandomAesKeyBase64() {
        byte[] salt = new byte[16];
        byte[] keyBytes = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(keyBytes);

        byte[] combined = new byte[48];
        System.arraycopy(salt, 0, combined, 0, 16);
        System.arraycopy(keyBytes, 0, combined, 16, 32);

        return Base64.getEncoder().encodeToString(combined);
    }
}