package io.yh.security.config.jwt;

import io.jsonwebtoken.Claims;
import io.yh.security.token.TokenType;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Hook to add or modify claims for issued tokens.
 */
public interface JwtClaimCustomizer {
    void customize(Claims claims, UserDetails userDetails, TokenType tokenType);

    JwtClaimCustomizer NOOP = (claims, userDetails, tokenType) -> {};
}
