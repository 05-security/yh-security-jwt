package com.yh.security.config;

import com.yh.security.core.JwtProvider;
import com.yh.security.core.JwtProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * ✅ Spring Boot AutoConfiguration
 * - JWT 기반 SecurityFilterChain 자동 설정
 */
@AutoConfiguration
@EnableConfigurationProperties(JwtProperties.class)
@RequiredArgsConstructor
public class SecurityAutoConfiguration {

    private final CustomAccessDeniedHandler deniedHandler;
    private final CustomAuthenticationEntryPoint entryPoint;
    private final JwtProvider jwtProvider;

    /**
     * ✅ JwtAuthenticationFilter Bean 등록
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtProvider);
    }

    /**
     * ✅ SecurityFilterChain 설정
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .accessDeniedHandler(deniedHandler)
                        .authenticationEntryPoint(entryPoint))
                .authorizeHttpRequests(req -> req
                        .requestMatchers("/login", "/auth/**", "/public/**").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
