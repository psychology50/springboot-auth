package com.example.Auth.global.common.jwt.entity;

import com.example.Auth.domain.user.domain.RoleType;
import com.example.Auth.domain.user.domain.User;
import lombok.Builder;

@Builder
public record JwtUserInfo(
        Long id,
        Integer githubId,
        RoleType role
) {
    public static JwtUserInfo of(Long id, Integer githubId, RoleType role) {
        return new JwtUserInfo(id, githubId, role);
    }

    public static JwtUserInfo from(User user) {
        return new JwtUserInfo(user.getId(), user.getGithubId(), user.getRole());
    }

    @Override public String toString() {
        return String.format("JwtUserInfo(id=%d, githubId=%d, role=%s)", id, githubId, role);
    }
}