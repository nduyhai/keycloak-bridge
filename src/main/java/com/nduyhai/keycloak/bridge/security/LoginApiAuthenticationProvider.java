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
        String username = (authentication.getName() == null) ? "" : authentication.getName();
        String password = (authentication.getCredentials() == null) ? "" : authentication.getCredentials().toString();

        var user = loginApi.login(username, password);
        if (user == null) {
            throw new BadCredentialsException("Invalid username or password");
        }

        // return an AUTHENTICATED token (3-arg constructor) with authorities
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        // Principal username == user_id => ID token sub == user_id
        var principal = new BridgeUserDetails(user.userId(), user.name(), user.email(), authorities);
        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
    }

    @Override
    public boolean supports(@NonNull Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
