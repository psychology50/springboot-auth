package com.example.Auth.global.config.redis;

import jakarta.persistence.Id;
import org.springframework.data.redis.core.RedisHash;

@RedisHash("refreshToken")
public class RefreshToken {
    @Id
    private final Long userId;
    private final String token;
    private final Integer githubId;

    private RefreshToken(Long userId, String token, Integer githubId) {
        this.userId = userId;
        this.token = token;
        this.githubId = githubId;
    }

    public static RefreshToken of(Long userId, String refreshToken, Integer githubId) {
        return new RefreshToken(userId, refreshToken, githubId);
    }

    public Long getUserId() {
        return userId;
    }

    public String getToken() {
        return token;
    }
    public Integer getGithubId() {
        return githubId;
    }
}
