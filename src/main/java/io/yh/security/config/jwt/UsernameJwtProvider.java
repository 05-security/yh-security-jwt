package io.yh.security.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * JWT provider that uses username as the subject for simple token creation/parsing.
 */
public class UsernameJwtProvider extends JwtProvider<String> {

    @Override
    public Claims buildClaims(String username) {
        return Jwts.claims().setSubject(username);
    }

    @Override
    public String parseClaims(Claims claims) {
        return claims.getSubject();
    }
}
