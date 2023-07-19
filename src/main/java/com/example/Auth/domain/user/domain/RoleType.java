package com.example.Auth.domain.user.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum RoleType {
    Admin("ROLE_ADMIN"),
    USER("ROLE_USER");

    private final String role;
}
