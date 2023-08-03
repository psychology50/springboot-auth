package com.example.Auth.global.config.redis;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Repository
@EnableRedisRepositories
public class RefreshTokenRepository {
    private final RedisTemplate<Long, Object> redisTemplate;

    public RefreshTokenRepository(RedisTemplate<Long, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void save(RefreshToken refreshToken, int refreshExpireTime) {
        Long key = refreshToken.getUserId();
        Map<String, Object> refreshTokenData = Map.of(
                "refresh", refreshToken.getToken(),
                "githubId", refreshToken.getGithubId()
        );

        ValueOperations<Long, Object> valueOperation = redisTemplate.opsForValue();
        valueOperation.set(key, refreshTokenData);
        redisTemplate.expire(key, refreshExpireTime, TimeUnit.HOURS);
    }

    public Optional<RefreshToken> findById(Long userId) {
        ValueOperations<Long, Object> valueOperation = redisTemplate.opsForValue();
        Map<Long, Object> data = (Map<Long, Object>) valueOperation.get(userId);

        if (Objects.isNull(data)) {
            return Optional.empty();
        }

        String refreshToken = data.get("refresh").toString();
        Integer githubId = (Integer) data.get("githubId");
        return Optional.of(RefreshToken.of(userId, refreshToken, githubId));
    }
}
