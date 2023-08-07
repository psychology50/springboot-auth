package com.example.Auth.global.config.security.jwt;

import com.example.Auth.domain.user.dto.UserAuthenticateDto;
import com.example.Auth.global.config.redis.RefreshTokenRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {
    private JwtTokenProvider JwtTokenProvider;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    private UserAuthenticateDto dto;
    private static final String jwtSecretKey = "fakeSecretKeyHelloImVeryNiceGuyAndYouHaHaWhyWhy";

    @BeforeEach
    public void setUp() {
        JwtTokenProvider = new JwtTokenProviderImpl(jwtSecretKey, 1, 1, refreshTokenRepository);
        dto = createDto();
    }

    @Test
    public void testGenerateAccessToken() {
        // when
        String accessToken = JwtTokenProvider.generateAccessToken(dto);

        // then
        System.out.println("accessToken : " + accessToken);
        assertNotNull(accessToken);
    }

    @Test
    public void testGenerateRefreshToken() {
        // when
        String refreshToken = JwtTokenProvider.generateRefreshToken(dto);

        // then
        System.out.println("refreshToken : " + refreshToken);
        assertNotNull(refreshToken);
    }

    @Test
    public void testIsTokenExpired() {
        // given
        String header = "Bearer " + createExpiredToken(dto);

        // when
        assertThrows(RuntimeException.class, () -> JwtTokenProvider.resolveToken(header));
    }

    @Test
    public void testAccessTokenExpiredAndRefreshTokenValid() {
        // given
        String expiredAccessToken = JwtTokenProvider.generateAccessToken(dto);
        String refreshToken = JwtTokenProvider.generateRefreshToken(dto);
        String header = "Bearer " + expiredAccessToken;

        ReflectionTestUtils.setField(JwtTokenProvider, "accessTokenExpirationTime", -1);

//        given(refreshTokenRepository.findById(anyLong())).willReturn(
//                Optional.of(RefreshToken.of(dto.getId(), refreshToken, dto.getGithubId()))
//        );

        // when
        JwtTokenProvider.resolveToken(header);

        // then
//        refreshTokenRepository.findById(dto.getId())
    }

    @Test
    public void testAccessTokenExpiredAndRefreshTokenExpired() {
        // given
        String expiredAccessToken = createExpiredToken(dto);
        String header = "Bearer " + expiredAccessToken;

//        given(refreshTokenRepository.findById(anyString())).willReturn(Optional.empty());

        // when & then
        assertThrows(RuntimeException.class, () -> JwtTokenProvider.resolveToken(header));
    }

    private UserAuthenticateDto createDto() {
        return UserAuthenticateDto.of(1L);
    }

    private String createExpiredToken(UserAuthenticateDto dto) {
        int expirationTime = -1;

        return Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(dto))
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(createExpireDate(expirationTime))
                .compact();
    }

    private static Map<String, Object> createHeader() {
        return Map.of("typ", "JWT",
                "alg", "HS256",
                "regDate", System.currentTimeMillis());
    }

    private static Map<String, Object> createClaims(UserAuthenticateDto dto) {
        return Map.of("userId", dto.getId());
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
}