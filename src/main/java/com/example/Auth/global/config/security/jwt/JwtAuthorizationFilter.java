package com.example.Auth.global.config.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * 지정한 URL 별로 JWT 유효성 검증을 수행하며, 직접적인 사용자 인증을 확인합니다.
 */
@Log4j2
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        List<String> jwtIgnoreUrls = List.of(
                "/", "/favicon.ico", "/api-docs/**", "/test/**",
                "/api/v1/auth/login", "/api/v1/auth/refresh"
        );

        if (isIgnoreUrlOrOptionRequest(jwtIgnoreUrls, request.getRequestURI(), request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwtHeader = request.getHeader("Authorization");
        log.info("jwtHeader: {}", jwtHeader);

        try {
            isJwtValid(jwtHeader);
        } catch (Exception e) {
            log.error("doFilterInternal error: {}", e.getMessage());
        }
    }

    private boolean isIgnoreUrlOrOptionRequest(List<?> jwtIgnoreUrls, String url, HttpServletRequest request) {
        return jwtIgnoreUrls.contains(url) || request.getMethod().equals("OPTIONS");
    }

    private void isJwtValid(String header) {
        if (header == null || !header.startsWith("Bearer "))
            throw new RuntimeException("JWT Token is missing");



    }
}
