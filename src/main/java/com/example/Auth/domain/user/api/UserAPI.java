package com.example.Auth.domain.user.api;

import com.example.Auth.domain.user.application.UserAuthService;
import com.example.Auth.domain.user.application.UserSearchService;
import com.example.Auth.domain.user.dto.TokenDto;
import com.example.Auth.domain.user.dto.UserAuthenticateDto;
import com.example.Auth.domain.user.dto.UserDto;
import com.example.Auth.global.config.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Log4j2
public class UserAPI {
    private final UserAuthService userAuthService;
    private final UserSearchService userSearchService;
    private final JwtTokenProvider jwtTokenProvider;
    private static RedisTemplate<String, String> redisTemplate;

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody UserAuthenticateDto dto) {
        TokenDto tokenDto = TokenDto.of(
                jwtTokenProvider.generateAccessToken(dto),
                jwtTokenProvider.generateRefreshToken(dto)
        );
        log.info("access token: {}", tokenDto.getAccess());
        log.info("refresh token: {}", tokenDto.getRefresh());

        return ResponseEntity.ok(tokenDto);
    }

    @GetMapping("/test")
    @Secured("ROLE_USER")
    public ResponseEntity<?> test(@RequestHeader("Authorization") String header) {
        log.info("header : {}", header);
        String refreshToken = redisTemplate.opsForValue().get("1");
        log.info("refresh token : {}", refreshToken);

        return ResponseEntity.ok("성공");
    }
}
