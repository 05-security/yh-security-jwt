package com.yh.security.core;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * ✅ 사용자가 직접 구현할 수 있도록 인터페이스만 제공
 */
public interface JwtUserDetailsService extends UserDetailsService {
    @Override
    UserDetails loadUserByUsername(String username);
}
