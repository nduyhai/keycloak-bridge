package com.nduyhai.keycloak.bridge.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class LoginApiClient {
    private final WebClient web;

    public LoginApiClient(@Value("${app.loginApiBaseUrl}") String baseUrl) {
        this.web = WebClient.builder().baseUrl(baseUrl).build();
    }

    public LoginResponse login(String username, String password) {
        return web.post()
                .uri("/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new LoginRequest(username, password))
                .retrieve()
                .bodyToMono(LoginResponse.class)
                .block();
    }

    public record LoginRequest(String username, String password) {
    }

    public record LoginResponse(String userId, String name, String email) {
    }
}