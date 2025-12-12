package io.yh.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "yh-jwt")
public class SecurityProperties {
    private String jwtSecret;
    private String refreshSecret;

    private String jwtHeaderString = "Authorization";
    private String refreshHeaderString = "Refresh";
    private String tokenPrefix = "Bearer ";

    private int accessTokenExpiration = 3600000;
    private int refreshTokenExpiration = 604800000;

    // Cookie settings
    private boolean cookieSecure = true;
    private String cookieSameSite = "Lax"; // Lax | Strict | None
    private String cookieDomain;
    private String cookiePath = "/";

    // Security chain settings
    private List<String> permitAll = new ArrayList<>(List.of("/**"));

    private String issuer;
    private String algorithm;
}
