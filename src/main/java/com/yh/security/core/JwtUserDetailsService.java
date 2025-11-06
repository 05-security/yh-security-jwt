package com.yh.security.core;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtUserDetailsService {
    UserDetails loadUserByUsername(String username);
}
