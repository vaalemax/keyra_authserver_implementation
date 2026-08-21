package com.portfolio.keyra.service;

import com.portfolio.keyra.model.dto.CanRequest;
import com.portfolio.keyra.model.dto.CanResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class AuthorizationClient {

    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final RestClient restClient;

    @Value("${authserver.base-url:http://localhost:9000}")
    private String authserverBaseUrl;

    public AuthorizationClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        this.authorizedClientManager = authorizedClientManager;
        this.restClient = RestClient.create();
    }

    public boolean can(Authentication authentication, String subject, String action) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            return false; // fail-closed
        }

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId(oauthToken.getAuthorizedClientRegistrationId())
                .principal(authentication)
                .build();

        OAuth2AuthorizedClient client = authorizedClientManager.authorize(authorizeRequest);
        if (client == null) return false;

        try {
            CanResponse response = restClient.post()
                    .uri(authserverBaseUrl + "/keyra/auth/can")
                    .header("Authorization", "Bearer " + client.getAccessToken().getTokenValue())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new CanRequest(subject, action))
                    .retrieve()
                    .body(CanResponse.class);

            System.out.println(response);
            return response != null && response.can();
        } catch (Exception ex) {
            return false; // fail-closed
        }
    }
}