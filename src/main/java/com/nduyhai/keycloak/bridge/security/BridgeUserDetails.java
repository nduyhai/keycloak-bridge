package com.nduyhai.keycloak.bridge.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public record BridgeUserDetails(
        String userId,
        String displayName,
        String email,
        Collection<? extends GrantedAuthority> authorities
) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    // IMPORTANT: OIDC "sub" derives from the principal name -> we set it to userId.
    @Override
    public String getUsername() {
        return userId;
    }

    @Override
    public String getPassword() {
        return "";
    } // not stored here

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}