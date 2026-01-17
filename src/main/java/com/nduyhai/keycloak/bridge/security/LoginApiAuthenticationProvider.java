package com.nduyhai.keycloak.bridge.security;

import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class LoginApiAuthenticationProvider implements AuthenticationProvider {
    private final LoginApiClient loginApi;

    public LoginApiAuthenticationProvider(LoginApiClient loginApi) {
        this.loginApi = loginApi;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = String.valueOf(authentication.getPrincipal());
        String password = String.valueOf(authentication.getCredentials());

        LoginApiClient.LoginResponse res;
        try {
            res = loginApi.login(username, password);
        } catch (Exception e) {
            throw new BadCredentialsException("Login failed", e);
        }

        if (res == null || res.userId() == null || res.userId().isBlank()) {
            throw new BadCredentialsException("Invalid credentials");
        }

        var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        // Principal username == user_id => ID token sub == user_id
        var principal = new BridgeUserDetails(res.userId(), res.name(), res.email(), authorities);

        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
    }

    @Override
    public boolean supports(@NonNull Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
