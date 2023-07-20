package com.example.Auth.global.config.security.jwt;

import com.example.Auth.domain.user.dto.UserDto;
import io.jsonwebtoken.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Component
@Log4j2
public class JwtTokenProvider {
    // TODO : @Value로 jwtSecretKey를 가져오는 방법을 찾아보자.
    private static final String jwtSecretKey = "exampleSecretKeyForSpringBootProjectAtSubRepository";

    /**
     * 헤더로부터 토큰을 추출하는 메서드
     * @param header : 메시지 헤더
     */
    public static void resolveToken(String header) {
        if (header == null || !header.startsWith("Bearer "))
            throw new RuntimeException("JWT Token is missing");

        String token = getTokenFromHeader(header);
        if (!isValidToken(token))
            throw new RuntimeException("JWT Token is invalid");

        String userId = getUserIdFromToken(token);
        log.info("userId: {}", userId);

        if (userId == null || userId.isBlank())
            throw new RuntimeException("userId is null or blank");
    }


//    public Authentication getAuthentication(String token) {
//        Claims claims = getClaimsFormToken(token);
//        String userName = claims.getSubject();
//        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
//
//        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
//    }

    /**
     * 사용자 정보 기반으로 액세스 토큰을 생성하는 메서드
     * @param dto UserDto : 사용자 정보
     * @return String : 토큰
     */
    public static String generateAccessToken(UserDto dto) {
        return Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(dto))
                .setSubject(String.valueOf(dto.getId()))
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(createExpireDate(1))
                .compact();
    }

    /**
     * 사용자 정보 기반으로 리프레시 토큰을 생성하는 메서드
     * @param dto UserDto : 사용자 정보
     * @return String : 토큰
     */
    public static String generateRefreshToken(UserDto dto) {
        return Jwts.builder()
                .setHeader(createHeader())
                .setSubject(String.valueOf(dto.getName()))
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(createExpireDate(24 * 3))
                .compact();
    }

    private static boolean isValidToken(String token) {
        try {
            Claims claims = getClaimsFormToken(token);

            log.info("expireTime: {}", claims.getExpiration());
            log.info("userId: {}", claims.get("userId", String.class));
            log.info("userName: {}", claims.get("userName", String.class));

            return true;
        } catch (ExpiredJwtException e) {
            log.error("Token Expired");
            return false;
        } catch (JwtException e) {
            log.error("Token Tampered");
            return false;
        } catch (NullPointerException e) {
            log.error("Token is null");
            return false;
        }
    }

    private static Map<String, Object> createHeader() {
        return Map.of("typ", "JWT",
                      "alg", "HS256",
                      "regDate", System.currentTimeMillis());
    }

    private static Map<String, Object> createClaims(UserDto dto) {
        return Map.of("userId", dto.getId(),
                      "userEmail", dto.getEmail(),
                      "userRole", dto.getRole());
    }

    private static Key createSignature() {
        byte[] secretKeyBytes = Base64.getDecoder().decode(jwtSecretKey);
        return new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    private static Date createExpireDate(int time) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, time);
        return calendar.getTime();
    }

    private static String getTokenFromHeader(String header) {
        return header.split(" ")[1];
    }

    private static String getUserIdFromToken(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.get("userId", String.class);
    }

    private static Claims getClaimsFormToken(String token) {
        return Jwts.parser()
                .setSigningKey(Base64.getDecoder().decode(jwtSecretKey))
                .parseClaimsJws(token)
                .getBody();
    }
}
