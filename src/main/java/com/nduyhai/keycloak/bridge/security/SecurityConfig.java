package com.nduyhai.keycloak.bridge.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class SecurityConfig {

    @Value("${app.issuer}")
    String issuer;

    @Value("${app.client.id}")
    String clientId;

    @Value("${app.client.secret}")
    String clientSecret;

    @Value("${app.client.redirectUrl}")
    String redirectUrl;


    private static RSAKey generateRsa() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            KeyPair kp = g.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                    .privateKey((RSAPrivateKey) kp.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 1) Authorization Server chain (OIDC endpoints):
     * - /oauth2/authorize, /oauth2/token, /oauth2/jwks, /.well-known/openid-configuration, /userinfo...
     */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer as = new OAuth2AuthorizationServerConfigurer();
        var endpointsMatcher = as.getEndpointsMatcher();

        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                )
                .with(as, cfg -> cfg
                        .oidc(Customizer.withDefaults())
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(endpointsMatcher)
                );

        return http.build();
    }


    /**
     * 2) App chain (login UI + your pages)
     */
    @Bean
    @Order(2)
    SecurityFilterChain appChain(HttpSecurity http,
                                 LoginApiAuthenticationProvider provider) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/login",
                                "/assets/**",
                                "/favicon.ico",
                                "/error",
                                "/.well-known/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .authenticationProvider(provider)
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/", true)
                        .failureUrl("/login?error")
                )
                .logout(logout -> logout.logoutUrl("/logout"));

        return http.build();
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Register Keycloak as a confidential client of Bridge (for brokering).
     * Replace redirectUri with your Keycloak broker callback:
     * http://localhost:8080/realms/<realm>/broker/<alias>/endpoint
     */
    @Bean
    RegisteredClientRepository registeredClientRepository(PasswordEncoder enc) {
        RegisteredClient keycloak = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(enc.encode(clientSecret))
                .clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUrl)
                .scope("openid")
                .scope("profile")
                .scope("email")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true) // PKCE (OAuth2.1 style)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(keycloak);
    }

    @Bean
    OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    OAuth2AuthorizationConsentService consentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    // ===== JWT signing keys (DEV) =====
    @Bean
    JWKSource<SecurityContext> jwkSource() {
        RSAKey rsa = generateRsa();
        JWKSet jwkSet = new JWKSet(rsa);
        return (selector, context) -> selector.select(jwkSet);
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return NimbusJwtDecoder.withJwkSource(jwkSource).build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (ctx) -> {
            var auth = ctx.getPrincipal();
            if (auth == null) return;

            if (!(auth.getPrincipal() instanceof BridgeUserDetails u)) return;

            // ID Token
            if (OidcParameterNames.ID_TOKEN.equals(ctx.getTokenType().getValue())) {
                ctx.getClaims().claim("email", u.email());
                ctx.getClaims().claim("name", u.displayName());
                ctx.getClaims().claim("user_id", u.getUsername()); // same as sub
            }

            // Optional: Access Token
            if ("access_token".equals(ctx.getTokenType().getValue())) {
                ctx.getClaims().claim("user_id", u.getUsername());
            }
        };
    }
}