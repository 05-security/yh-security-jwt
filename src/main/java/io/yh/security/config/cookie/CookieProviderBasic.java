package io.yh.security.config.cookie;

import io.yh.security.config.SecurityProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;

public class CookieProviderBasic implements CookieProvider {

    private final SecurityProperties properties;

    public CookieProviderBasic(SecurityProperties properties) {
        this.properties = properties;
    }

    @Override
    public Cookie buildCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(properties.isCookieSecure());
        cookie.setPath(properties.getCookiePath());
        if (properties.getCookieDomain() != null && !properties.getCookieDomain().isBlank()) {
            cookie.setDomain(properties.getCookieDomain());
        }
        cookie.setMaxAge(maxAge);
        String sameSite = properties.getCookieSameSite();
        if (sameSite != null && !sameSite.isBlank()) {
            cookie.setAttribute("SameSite", sameSite);
        }
        return cookie;
    }

    @Override
    public String getCookieStringByRequest(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(name))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
