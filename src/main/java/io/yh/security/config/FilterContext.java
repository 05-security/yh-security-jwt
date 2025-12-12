package io.yh.security.config;

import io.yh.security.config.cookie.CookieProvider;
import io.yh.security.config.jwt.JwtClaimCustomizer;
import io.yh.security.config.jwt.JwtProvider;
import io.yh.security.store.RefreshTokenStore;
import io.yh.security.token.TokenResponseWriter;
import lombok.Builder;
import org.springframework.security.authentication.AuthenticationManager;

@Builder
public record FilterContext(
        AuthenticationManager authenticationManager,
        JwtProvider jwtProvider,
        CookieProvider cookieProvider,
        SecurityProperties properties,
        RefreshTokenStore refreshTokenStore,
        TokenResponseWriter tokenResponseWriter,
        JwtClaimCustomizer jwtClaimCustomizer
) {}
