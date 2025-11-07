package io.yh.security.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.function.Function;

public abstract class JwtProvider<T> {

    public SecretKey getKey(String secretKey) {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    public abstract Claims buildClaims(T member);
    public abstract T parseClaims(Claims claims);

    public String createToken(Claims claims, int validityInMilliseconds, SecretKey key) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key)
                .compact();
    }

    public Claims createClaims(Function<Claims, Claims> claimBuilder) {
        return claimBuilder.apply(Jwts.claims());
    }

    public T parseToken(String token, SecretKey key) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return parseClaims(claims);
    }

    public Claims createJwtClaims(T member) {
        return buildClaims(member);
    }

    public Claims createRefreshClaims(T member) {
        return buildClaims(member);
    }

    public T parseJwtToken(String token, SecretKey key) {
        return parseToken(token, key);
    }

    public T parseRefreshToken(String token, SecretKey key) {
        return parseToken(token, key);
    }
}
