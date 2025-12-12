package io.yh.security.auth;

import io.yh.security.config.SecurityProperties;
import io.yh.security.config.cookie.CookieProvider;
import io.yh.security.config.jwt.JwtProvider;
import io.yh.security.filter.SuccessHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import io.yh.security.store.RefreshTokenStore;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final CookieProvider cookieProvider;
    private final SecurityProperties properties;
    private final JwtProvider<String> jwtProvider;
    private final UserDetailsService userDetailsService;
    private final SuccessHandler successHandler;
    private final RefreshTokenStore refreshTokenStore;

    public void reissue(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = cookieProvider.getCookieStringByRequest(request, properties.getRefreshHeaderString());
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalStateException("Refresh token missing");
        }
        SecretKey refreshKey = jwtProvider.getKey(properties.getRefreshSecret());
        String username = jwtProvider.parseRefreshToken(refreshToken, refreshKey);
        if (!refreshTokenStore.validate(username, refreshToken)) {
            throw new IllegalStateException("Refresh token invalid");
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        successHandler.successHandler(request, response, userDetails);
    }
}
