package com.example.Auth.domain.user.dto;

public class UserAuthenticateDto {
    private Long id;
    private String name;

    private UserAuthenticateDto(Long id, String name) {
        this.id = id;
        this.name = name;
    }

    public static UserAuthenticateDto of(Long id, String name) {
        return new UserAuthenticateDto(id, name);
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}
