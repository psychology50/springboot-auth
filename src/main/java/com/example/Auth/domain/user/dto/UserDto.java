package com.example.Auth.domain.user.dto;

import com.example.Auth.domain.user.domain.RoleType;
import com.example.Auth.domain.user.domain.User;
import lombok.Builder;
import lombok.Getter;

@Getter
public class UserDto {
    private Long id;
    private String name;
    private String email;
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
