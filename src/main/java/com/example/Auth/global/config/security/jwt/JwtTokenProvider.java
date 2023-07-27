package com.example.Auth.global.config.security.jwt;

import com.example.Auth.domain.user.dto.UserAuthenticateDto;
import com.example.Auth.domain.user.dto.UserDto;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
@Log4j2
public class JwtTokenProvider {
    private static String jwtSecretKey;
    private static int accessTokenExpirationTime;
    private static int refreshTokenExpirationTime;
    private static RedisTemplate<String, String> redisTemplate;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String jwtSecretKey,
            @Value("${jwt.token.access-expiration-time}") int accessTokenExpirationTime,
            @Value("${jwt.token.refresh-expiration-time}") int refreshTokenExpirationTime,
            RedisTemplate<String, String> redisTemplate
    ) {
        this.jwtSecretKey = jwtSecretKey;
        this.accessTokenExpirationTime = accessTokenExpirationTime;
        this.refreshTokenExpirationTime = refreshTokenExpirationTime;
        this.redisTemplate = redisTemplate;
    }

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

        Long userId = getUserIdFromToken(token);
        if (userId == null)
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
    public static String generateAccessToken(UserAuthenticateDto dto) {
        return Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(dto))
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(createExpireDate(accessTokenExpirationTime))
                .compact();
    }

    /**
     * 사용자 정보 기반으로 리프레시 토큰을 생성하는 메서드
     * @param dto UserDto : 사용자 정보
     * @return String : 토큰
     */
    public static String generateRefreshToken(UserAuthenticateDto dto) {
        String token = Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(dto))
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(createExpireDate(refreshTokenExpirationTime))
                .compact();

        redisTemplate.opsForValue().set(
                dto.getId().toString(),
                token,
                refreshTokenExpirationTime,
                TimeUnit.HOURS
        );
        return token;
    }

    private static boolean isValidToken(String token) {
        try {
            Claims claims = getClaimsFormToken(token);

            log.info("expireTime: {}", claims.getExpiration());
            log.info("userId: {}", claims.get("userId", Long.class));
            log.info("userName: {}", claims.get("userName", String.class));

            return true;
        } catch (ExpiredJwtException e) {
            log.error("Token Expired");
            return false;
        } catch (JwtException e) {
            log.error("error message: {}", e.getMessage());
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

    private static Map<String, Object> createClaims(UserAuthenticateDto dto) {
        return Map.of("userId", dto.getId()
                     ,"userName", dto.getName());
    }

    private static Key createSignature() {
        byte[] secretKeyBytes = Base64.getDecoder().decode(jwtSecretKey);
        return new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    private static Date createExpireDate(int expirationTime) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expirationTime);
        return calendar.getTime();
    }

    private static String getTokenFromHeader(String header) {
        return header.split(" ")[1];
    }

    private static Long getUserIdFromToken(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.get("userId", Long.class);
    }

    private static Claims getClaimsFormToken(String token) {
        return Jwts.parser()
                .setSigningKey(Base64.getDecoder().decode(jwtSecretKey))
                .parseClaimsJws(token)
                .getBody();
    }
}
