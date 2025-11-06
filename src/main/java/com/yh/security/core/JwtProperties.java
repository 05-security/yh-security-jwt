package com.yh.security.core;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String secret;      // JWT 서명에 사용할 시크릿 키
    private long expiration;    // 토큰 만료 시간(ms)

}
