package com.example.Auth.global.config.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import net.minidev.json.JSONObject;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 지정한 URL 별로 JWT 유효성 검증을 수행하며, 직접적인 사용자 인증을 확인합니다.
 */
@Log4j2
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        List<String> jwtIgnoreUrls = List.of(
                "/api/v1/users/login", "/api/v1/users/refresh"
        );

        if (isIgnoreUrlOrOptionRequest(jwtIgnoreUrls, request.getRequestURI(), request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwtHeader = request.getHeader("Authorization");
        log.info("jwtHeader: {}", jwtHeader);

        try {
            isJwtValid(jwtHeader);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("doFilterInternal error: {}", e.getMessage());
            sendResponse(response, e);
        }
    }

    private boolean isIgnoreUrlOrOptionRequest(List<?> jwtIgnoreUrls, String url, HttpServletRequest request) {
        return jwtIgnoreUrls.contains(url) || request.getMethod().equals("OPTIONS");
    }

    private void isJwtValid(String header) {
        if (header == null || !header.startsWith("Bearer "))
            throw new RuntimeException("JWT Token is missing");

        String token = TokenUtils.getTokenFromHeader(header);

        if (!TokenUtils.isValidToken(token))
            throw new RuntimeException("JWT Token is invalid");

        String userId = TokenUtils.getUserIdFromToken(token);
        log.info("[+] userId: {}", userId);

        if (userId == null || userId.equalsIgnoreCase(""))
            throw new RuntimeException("Token is not userId");
    }

    private void sendResponse(HttpServletResponse response, Exception e) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(401);

        PrintWriter out = response.getWriter();
        out.print(getResponseJson(e));
        out.flush();
        out.close();
    }

    private JSONObject getResponseJson(Exception e) {
        String msg;

        if (e instanceof ExpiredJwtException) {
            msg = "Token Expired";
        } else if (e instanceof SignatureException) {
            msg = "Token SignatureException";
        } else if (e instanceof JwtException) {
            msg = "Token Parsing JwtException";
        } else {
            msg = "Token is invalid";
        }

        Map<String, Object> jsonMap = Map.of(
                "status", 401,
                "code", 999,
                "message", msg,
                "detail", e.getMessage()
        );
        return new JSONObject(jsonMap);
    }
}
