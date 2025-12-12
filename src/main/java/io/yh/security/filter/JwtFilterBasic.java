package io.yh.security.filter;

import io.yh.security.config.FilterContext;
import io.yh.security.config.SecurityProperties;
import io.yh.security.config.jwt.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtFilterBasic extends OncePerRequestFilter {

    private final JwtProvider<String> jwtProvider;
    private final SecurityProperties properties;
    private final UserDetailsService userDetailsService;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    public JwtFilterBasic(FilterContext context, UserDetailsService userDetailsService, AuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtProvider = (JwtProvider<String>) context.jwtProvider();
        this.properties = context.properties();
        this.userDetailsService = userDetailsService;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader(properties.getJwtHeaderString());

        if (header == null || header.isBlank()
                || header.equalsIgnoreCase("null")
                || header.equalsIgnoreCase("undefined")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.replace(properties.getTokenPrefix(), "").trim();
        if (token.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            SecretKey key = jwtProvider.getKey(properties.getJwtSecret());
            String username = jwtProvider.parseJwtToken(token, key);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            authenticationEntryPoint.commence(request, response, new InsufficientAuthenticationException(ex.getMessage(), ex));
        }
    }
}
