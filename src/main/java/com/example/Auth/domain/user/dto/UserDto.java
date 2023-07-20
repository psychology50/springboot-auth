package com.example.Auth.domain.user.dto;

import com.example.Auth.domain.user.domain.RoleType;
import com.example.Auth.domain.user.domain.RoleTypeDeserializer;
import com.example.Auth.domain.user.domain.User;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class UserDto {
    private Long id;
    private String name;
    private String email;
    @JsonDeserialize(using = RoleTypeDeserializer.class)
    private RoleType role;

    public UserDto(User user) {
        this.id = user.getId();
        this.name = user.getName();
        this.email = user.getEmail();
        this.role = user.getRole();
    }

    public User toEntity() {
        return User.builder()
                .id(id)
                .name(name)
                .email(email)
                .role(role)
                .build();
    }
}
