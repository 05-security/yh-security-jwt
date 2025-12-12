package io.yh.security.util;

import io.yh.security.auth.AuthController;
import io.yh.security.auth.AuthService;
import io.yh.security.config.FilterContext;
import io.yh.security.filter.JwtAccessDeniedHandler;
import io.yh.security.filter.JwtAuthenticationEntryPoint;
import io.yh.security.filter.JwtFilterBasic;
import io.yh.security.filter.OAuthSuccessHandler;
import io.yh.security.social.DefaultSocialUserMapper;
import io.yh.security.social.SocialUserMapper;
import io.yh.security.social.YhOAuth2UserService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AutoConfiguration
@Import({AuthController.class, AuthService.class})
public class YhSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtFilterBasic jwtFilterBasic(FilterContext context, UserDetailsService userDetailsService, JwtAuthenticationEntryPoint entryPoint) {
        return new JwtFilterBasic(context, userDetailsService, entryPoint);
    }

    @Bean
    @ConditionalOnMissingBean
    public SocialUserMapper socialUserMapper() {
        return new DefaultSocialUserMapper();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAccessDeniedHandler jwtAccessDeniedHandler() {
        return new JwtAccessDeniedHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public YhOAuth2UserService yhOAuth2UserService(SocialUserMapper socialUserMapper) {
        return new YhOAuth2UserService(socialUserMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtFilterBasic jwtFilterBasic,
            YhOAuth2UserService yhOAuth2UserService,
            OAuthSuccessHandler oAuthSuccessHandler,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/login", "/auth/refresh", "/oauth2/**", "/login/oauth2/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                        .accessDeniedHandler(jwtAccessDeniedHandler)
                )
                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(userInfo -> userInfo.userService(yhOAuth2UserService))
                        .successHandler(oAuthSuccessHandler)
                )
                .addFilterBefore(jwtFilterBasic, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
