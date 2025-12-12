package io.yh.security.token;

import io.yh.security.config.SecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Writes issued tokens to response (headers/cookies/body). Override to customize delivery.
 */
public interface TokenResponseWriter {
    void writeTokens(HttpServletRequest request,
                     HttpServletResponse response,
                     String accessToken,
                     String refreshToken,
                     SecurityProperties properties);
}
