package com.portfolio.keyra.config;

import com.portfolio.keyra.model.User;
import com.portfolio.keyra.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;

@RequiredArgsConstructor
public class VaultUnlockFilter extends OncePerRequestFilter {

    public static final String VAULT_UNLOCKED_ATTR = "VAULT_UNLOCKED";

    private static final Set<String> ALWAYS_ALLOWED  = Set.of(
            "/vault/unlock", "/settings", "/logout", "/css", "/js", "/static/favicon.ico"
    );

    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean authenticated = authentication != null && authentication.isAuthenticated();
        String uri = request.getRequestURI();
        boolean isVaultLandingPage = "GET".equalsIgnoreCase(request.getMethod()) && uri.equals("/vault");


        if (!authenticated || isAlwaysAllowed(uri) || isVaultLandingPage) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<User> user = userRepository.findByUsername(authentication.getName());
        boolean requiresUnlock = user.map(User::isTwoFactorEnabled).orElse(false);

        if (requiresUnlock) {
            HttpSession session = request.getSession(false);
            boolean unlocked = session != null && Boolean.TRUE.equals(session.getAttribute(VAULT_UNLOCKED_ATTR));
            if (!unlocked) {
                response.sendRedirect(request.getContextPath() + "/vault");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isAlwaysAllowed(String uri) {
        return ALWAYS_ALLOWED.stream().anyMatch(uri::startsWith);
    }
}