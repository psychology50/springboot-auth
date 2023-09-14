package com.example.Auth.domain.user.service;


import com.example.Auth.domain.user.domain.User;
import com.example.Auth.domain.user.dto.UserAuthReq;
import com.example.Auth.global.common.jwt.entity.JwtUserInfo;
import com.example.Auth.global.common.jwt.util.JwtTokenProvider;
import com.example.Auth.global.common.redis.forbidden.ForbiddenTokenService;
import com.example.Auth.global.common.redis.refresh.RefreshToken;
import com.example.Auth.global.common.redis.refresh.RefreshTokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;

import static com.example.Auth.global.common.jwt.AuthConstants.ACCESS_TOKEN;
import static com.example.Auth.global.common.jwt.AuthConstants.REFRESH_TOKEN;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserAuthService {
    private final RefreshTokenService refreshTokenService;
    private final ForbiddenTokenService forbiddenTokenService;
    private final UserSearchService userSearchService;

    private final JwtTokenProvider jwtTokenProvider;

    public Map<String, String> login(UserAuthReq dto) {
        User user = userSearchService.findById(dto.getId());
        // TODO: add user password validation check

        JwtUserInfo jwtUserInfo = JwtUserInfo.from(user);

        String accessToken = jwtTokenProvider.generateAccessToken(jwtUserInfo);
        String refreshToken = refreshTokenService.issueRefreshToken(accessToken);
        log.debug("accessToken : {}, refreshToken : {}", accessToken, refreshToken);

        return Map.of(ACCESS_TOKEN.getValue(), accessToken, REFRESH_TOKEN.getValue(), refreshToken);
    }

    public void logout(String authHeader, String requestRefreshToken) {
        String accessToken = jwtTokenProvider.resolveToken(authHeader);
        Long userId = jwtTokenProvider.getUserIdFromToken(accessToken);

        refreshTokenService.logout(requestRefreshToken);
        forbiddenTokenService.register(accessToken, userId);
    }

    public Map<String, String> refresh(String requestRefreshToken) {
        RefreshToken refreshToken = refreshTokenService.refresh(requestRefreshToken);

        Long userId = refreshToken.getUserId();
        JwtUserInfo dto = JwtUserInfo.from(userSearchService.findById(userId));
        String accessToken = jwtTokenProvider.generateAccessToken(dto);

        return Map.of(ACCESS_TOKEN.getValue(), accessToken, REFRESH_TOKEN.getValue(), refreshToken.getToken());
    }
}
