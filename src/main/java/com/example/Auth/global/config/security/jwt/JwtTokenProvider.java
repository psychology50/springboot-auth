package com.example.Auth.global.config.security.jwt;

import com.example.Auth.domain.user.dto.UserAuthenticateDto;
import org.springframework.stereotype.Service;

@Service("jwtTokenProvider")
public interface JwtTokenProvider {
    void resolveToken(String header);

    String generateAccessToken(UserAuthenticateDto dto);
    String generateRefreshToken(UserAuthenticateDto dto);
}
