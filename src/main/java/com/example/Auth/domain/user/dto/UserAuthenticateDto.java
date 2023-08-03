package com.example.Auth.domain.user.dto;

import lombok.Getter;

@Getter
public class UserAuthenticateDto {
    private Long id;
    private Integer githubId;

    private UserAuthenticateDto(Long id, Integer githubId) {
        this.id = id;
        this.githubId = githubId;
    }

    public static UserAuthenticateDto of(Long id, Integer githubId) {
        return new UserAuthenticateDto(id, githubId);
    }

    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UserAuthenticateDto(");
        sb.append("id=").append(id);
        sb.append(", githubId=").append(githubId);
        sb.append(")");
        return sb.toString();
    }
}
