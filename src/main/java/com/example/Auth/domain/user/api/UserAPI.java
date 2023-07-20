package com.example.Auth.domain.user.api;

import com.example.Auth.domain.user.application.UserAuthService;
import com.example.Auth.domain.user.application.UserSearchService;
import com.example.Auth.domain.user.dto.TokenDto;
import com.example.Auth.domain.user.dto.UserDto;
import com.example.Auth.global.config.security.jwt.AuthConstants;
import com.example.Auth.global.config.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Log4j2
public class UserAPI {
    private final UserAuthService userAuthService;
    private final UserSearchService userSearchService;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody UserDto userDto) {
        TokenDto tokenDto = TokenDto.of(
                jwtTokenProvider.generateAccessToken(userDto),
                jwtTokenProvider.generateRefreshToken(userDto)
        );
        log.info("access token: {}", tokenDto.getAccess());
        log.info("refresh token: {}", tokenDto.getRefresh());

        return ResponseEntity.ok(tokenDto);
    }
}
