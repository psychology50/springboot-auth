package com.example.Auth.domain.user.dto;

import com.example.Auth.domain.user.domain.RoleType;
import com.example.Auth.domain.user.domain.RoleTypeDeserializer;
import com.example.Auth.domain.user.domain.User;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.persistence.Column;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class UserDto {
    private Long id;
    private String name;
    private String email;
    private Integer githubId;
    @JsonDeserialize(using = RoleTypeDeserializer.class)
    private RoleType role;

    public UserDto(User user) {
        this.id = user.getId();
        this.name = user.getName();
        this.email = user.getEmail();
        this.githubId = user.getGithubId();
        this.role = user.getRole();
    }

    public User toEntity() {
        return User.builder()
                .id(id)
                .name(name)
                .email(email)
                .githubId(githubId)
                .role(role)
                .build();
    }

    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UserDto(");
        sb.append("id=").append(id);
        sb.append(", name=").append(name);
        sb.append(", email=").append(email);
        sb.append(", githubId=").append(githubId);
        sb.append(", role=").append(role);
        sb.append(")");
        return sb.toString();
    }
}
