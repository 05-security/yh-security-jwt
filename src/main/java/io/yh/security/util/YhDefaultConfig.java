package io.yh.security.util;

import io.yh.security.config.FilterContext;
import io.yh.security.config.SecurityProperties;
import io.yh.security.config.cookie.CookieProvider;
import io.yh.security.config.cookie.CookieProviderBasic;
import io.yh.security.config.jwt.JwtClaimCustomizer;
import io.yh.security.config.jwt.JwtProvider;
import io.yh.security.config.jwt.UsernameJwtProvider;
import io.yh.security.filter.OAuthSuccessHandler;
import io.yh.security.filter.SuccessHandler;
import io.yh.security.store.RefreshTokenStore;
import io.yh.security.store.StatelessRefreshTokenStore;
import io.yh.security.token.DefaultTokenResponseWriter;
import io.yh.security.token.TokenResponseWriter;
import io.yh.security.config.jwt.JwtClaimCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

@Configuration(proxyBeanMethods = false)
public class YhDefaultConfig {

    @Bean
    @ConditionalOnMissingBean(JwtProvider.class)
    public JwtProvider<String> yhJwtProvider() {
        return new UsernameJwtProvider();
    }

    @Bean
    @ConditionalOnMissingBean(CookieProvider.class)
    public CookieProvider yhCookieProvider(SecurityProperties properties) {
        return new CookieProviderBasic(properties);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityProperties.class)
    public SecurityProperties yhJwtProperties() {
        return new SecurityProperties();
    }

    @Bean
    @ConditionalOnMissingBean(RefreshTokenStore.class)
    public RefreshTokenStore yhRefreshTokenStore() {
        return new StatelessRefreshTokenStore();
    }

    @Bean
    @ConditionalOnMissingBean(JwtClaimCustomizer.class)
    public JwtClaimCustomizer yhJwtClaimCustomizer() {
        return JwtClaimCustomizer.NOOP;
    }

    @Bean
    @ConditionalOnMissingBean(TokenResponseWriter.class)
    public TokenResponseWriter yhTokenResponseWriter(CookieProvider cookieProvider) {
        return new DefaultTokenResponseWriter(cookieProvider);
    }

    @Bean
    @ConditionalOnMissingBean(FilterContext.class)
    public FilterContext yhFilterContext(AuthenticationConfiguration authConfig,
                                         JwtProvider<?> jwtProvider,
                                         CookieProvider cookieProvider,
                                         SecurityProperties properties,
                                         RefreshTokenStore refreshTokenStore,
                                         TokenResponseWriter tokenResponseWriter,
                                         JwtClaimCustomizer jwtClaimCustomizer) throws Exception {
        return FilterContext.builder()
                .authenticationManager(authConfig.getAuthenticationManager())
                .jwtProvider(jwtProvider)
                .cookieProvider(cookieProvider)
                .properties(properties)
                .refreshTokenStore(refreshTokenStore)
                .tokenResponseWriter(tokenResponseWriter)
                .jwtClaimCustomizer(jwtClaimCustomizer)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean(SimpleUrlAuthenticationSuccessHandler.class)
    public SimpleUrlAuthenticationSuccessHandler yhOAuthSuccessHandler(FilterContext context) {
        return new OAuthSuccessHandler(context);
    }

    @Bean
    @ConditionalOnMissingBean(SuccessHandler.class)
    public SuccessHandler yhSuccessHandler(FilterContext context) {
        return new SuccessHandler(context);
    }
}
