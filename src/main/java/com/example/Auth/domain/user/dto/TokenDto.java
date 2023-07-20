package com.example.Auth.domain.user.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@AllArgsConstructor
public class TokenDto {
    private String access;
    private String refresh;

    public static TokenDto of(String access, String refresh) {
        return new TokenDto(access, refresh);
    }
    public static TokenDto empty() {
        return new TokenDto("", "");
    }
}
