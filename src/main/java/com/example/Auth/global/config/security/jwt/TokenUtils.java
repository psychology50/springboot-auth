package com.example.Auth.global.config.security.jwt;

import com.example.Auth.domain.user.dto.UserDto;
import io.jsonwebtoken.*;
import lombok.extern.log4j.Log4j2;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Log4j2
public class TokenUtils {
    // TODO : @Value로 jwtSecretKey를 가져오는 방법을 찾아보자.
    private static final String jwtSecretKey = "exampleSecretKey";

    /**
     * Header 내의 토큰을 추출하는 메서드
     * @param header : 헤더
     * @return String : 토큰
     */
    public static String getTokenFromHeader(String header) {
        return header.split(" ")[1];
    }

    /**
     * 토큰을 기반으로 사용자 정보를 반환하는 메서드
     * @param token String : 토큰
     * @return String : 사용자 정보
     */
    public static String parseTokenToUserInfo(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecretKey)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

/**
     * 토큰의 유효성을 검사하는 메서드
     * @param token : 토큰
     * @return boolean : 유효성 여부
     */
    public static boolean isValidToken(String token) {
        try {
            Claims claims = getClaimsFormToken(token);

            log.info("expireTime: {}", claims.getExpiration());
            log.info("userId: {}", claims.get("userId", String.class));
            log.info("userNm: {}", claims.get("userNm", String.class));

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

    /**
     * 토큰에서 사용자 정보를 반환받는 메서드
     * @param token : 토큰
     * @return String : 사용자 아이디
     */
    public static String getUserIdFromToken(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.get("userId", String.class);
    }

    /**
     * 사용자 정보 기반으로 토큰을 생성하는 메서드
     * @param userDto UserDto : 사용자 정보
     * @return String : 토큰
     */
    public static String generateJwtToken(UserDto dto) {
        return Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(dto))
                .setSubject(String.valueOf(dto.getId()))
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(createExpireDate())
                .compact();
    }

    private static Map<String, Object> createHeader() {
        return Map.of("typ", "JWT",
                      "alg", "HS256",
                      "regDate", System.currentTimeMillis());
    }

    private static Map<String, Object> createClaims(UserDto dto) {
        return Map.of("userId", dto.getId(),
                      "userName", dto.getName(),
                      "userEmail", dto.getEmail(),
                      "userRole", dto.getRole());
    }

    private static Key createSignature() {
        byte[] secretKeyBytes = Base64.getDecoder().decode(jwtSecretKey);
        return new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    private static Date createExpireDate() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, 8);
        return calendar.getTime();
    }

    private static Claims getClaimsFormToken(String token) {
        return Jwts.parser()
                .setSigningKey(Base64.getDecoder().decode(jwtSecretKey))
                .parseClaimsJws(token)
                .getBody();
    }
}
