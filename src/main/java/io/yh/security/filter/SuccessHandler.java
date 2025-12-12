package io.yh.security.filter;

import io.jsonwebtoken.Claims;
import io.yh.security.config.FilterContext;
import io.yh.security.config.SecurityProperties;
import io.yh.security.config.jwt.JwtClaimCustomizer;
import io.yh.security.config.jwt.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import io.yh.security.store.RefreshTokenStore;
import io.yh.security.token.TokenResponseWriter;
import io.yh.security.token.TokenType;

import javax.crypto.SecretKey;

@RequiredArgsConstructor
public class SuccessHandler {

    private final JwtProvider<String> jwtProvider;
    private final SecurityProperties properties;
    private final RefreshTokenStore refreshTokenStore;
    private final TokenResponseWriter tokenResponseWriter;
    private final JwtClaimCustomizer jwtClaimCustomizer;

    public SuccessHandler(FilterContext context) {
        this.jwtProvider = context.jwtProvider();
        this.properties = context.properties();
        this.refreshTokenStore = context.refreshTokenStore();
        this.tokenResponseWriter = context.tokenResponseWriter();
        this.jwtClaimCustomizer = context.jwtClaimCustomizer();
    }

    public void successHandler(HttpServletRequest request,
                               HttpServletResponse response,
                               UserDetails userDetails) {
        String accessToken = properties.getTokenPrefix() + buildJwtToken(userDetails);

        String refreshToken = buildRefreshToken(userDetails);
        refreshTokenStore.save(userDetails.getUsername(), refreshToken, properties.getRefreshTokenExpiration());

        tokenResponseWriter.writeTokens(request, response, accessToken, refreshToken, properties);
    }

    private String buildJwtToken(UserDetails userDetails) {
        SecretKey jwtKey = jwtProvider.getKey(properties.getJwtSecret());
        Claims jwtClaims = jwtProvider.createJwtClaims(userDetails.getUsername());
        jwtClaimCustomizer.customize(jwtClaims, userDetails, TokenType.ACCESS);
        return jwtProvider.createToken(jwtClaims, properties.getAccessTokenExpiration(), jwtKey);
    }

    private String buildRefreshToken(UserDetails userDetails) {
        SecretKey refreshKey = jwtProvider.getKey(properties.getRefreshSecret());
        Claims refreshClaims = jwtProvider.createRefreshClaims(userDetails.getUsername());
        jwtClaimCustomizer.customize(refreshClaims, userDetails, TokenType.REFRESH);
        return jwtProvider.createToken(refreshClaims, properties.getRefreshTokenExpiration(), refreshKey);
    }
}
