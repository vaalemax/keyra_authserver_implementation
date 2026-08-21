package com.portfolio.keyra.config;

import com.portfolio.keyra.repository.UserRepository;
import com.portfolio.keyra.service.AuditService;
import com.portfolio.keyra.service.KeyraOidcUserService;
import com.portfolio.keyra.service.RateLimitService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final AuditService auditService;

    private final CustomAuthenticationFailureHandler failureHandler;

    private final CustomAuthenticationSuccessHandler successHandler;

    private final CustomLogoutSuccessHandler logoutSuccessHandler;

    private final KeyraOidcUserService keyraOidcUserService;

    private final RateLimitService rateLimitService;

    private final UserRepository userRepository;

    public SecurityConfig(AuditService auditService,
                          CustomAuthenticationFailureHandler failureHandler,
                          CustomAuthenticationSuccessHandler successHandler,
                          CustomLogoutSuccessHandler logoutSuccessHandler,
                          KeyraOidcUserService keyraOidcUserService,
                          RateLimitService rateLimitService,
                          UserRepository userRepository) {
        this.auditService = auditService;
        this.failureHandler = failureHandler;
        this.successHandler = successHandler;
        this.keyraOidcUserService = keyraOidcUserService;
        this.logoutSuccessHandler = logoutSuccessHandler;
        this.rateLimitService = rateLimitService;
        this.userRepository = userRepository;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(rateLimitingFilter(), UsernamePasswordAuthenticationFilter.class)

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/",
                                "/login",
                                "/register",
                                "/css/**",
                                "/js/**",
                                "/favicon.ico",
                                "/.well-known/**",
                                "/error/**")
                        .permitAll()
                        .requestMatchers("/vault/setup-2fa").authenticated()
                        .requestMatchers("/api/password/generate").authenticated()
                        .requestMatchers("/api/session/**").authenticated()
                        .requestMatchers("/settings/**").authenticated()
                        .anyRequest().authenticated()
                )

                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll()
                )

                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .permitAll()
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(keyraOidcUserService))
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                )

                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                        .sessionRegistry(sessionRegistry())

                )

                .csrf(Customizer.withDefaults())

                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; " +
                                        "script-src 'self' 'unsafe-inline'; " +
                                        "style-src 'self' 'unsafe-inline'; " +
                                        "img-src 'self' data:; " +
                                        "font-src 'self'; " +
                                        "connect-src 'self';"
                                )
                        )
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .xssProtection(HeadersConfigurer.XXssConfig::disable)
                        .contentTypeOptions(contentTypeOptions -> {})
                )
                .addFilterAfter(new VaultUnlockFilter(userRepository), AuthorizationFilter.class);

        return http.build();
    }

    @Bean
    public RateLimitingFilter rateLimitingFilter() {
        return new RateLimitingFilter(auditService, rateLimitService);
    }

    @Bean
    public org.springframework.security.core.session.SessionRegistry sessionRegistry() {
        return new org.springframework.security.core.session.SessionRegistryImpl();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                .map(user -> org.springframework.security.core.userdetails.User
                        .withUsername(user.getUsername())
                        .password(user.getPasswordHash())
                        .roles("USER")
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found: "+username));
    }
}
