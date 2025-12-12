package io.yh.security.token;

import io.yh.security.config.SecurityProperties;
import io.yh.security.config.cookie.CookieProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

/**
 * Default writer: access token in header, refresh token in HttpOnly/Secure cookie.
 */
@RequiredArgsConstructor
public class DefaultTokenResponseWriter implements TokenResponseWriter {

    private final CookieProvider cookieProvider;

    @Override
    public void writeTokens(HttpServletRequest request,
                            HttpServletResponse response,
                            String accessToken,
                            String refreshToken,
                            SecurityProperties properties) {
        response.addHeader(properties.getJwtHeaderString(), accessToken);

        Cookie refreshTokenCookie = cookieProvider.buildCookie(
                properties.getRefreshHeaderString(),
                refreshToken,
                properties.getRefreshTokenExpiration());
        response.addCookie(refreshTokenCookie);

        response.setStatus(HttpStatus.OK.value());
    }
}
