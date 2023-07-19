package com.example.Auth.global.config.security.jwt;

public enum AuthConstants {
    AUTH_HEADER("Authorization"), TOKEN_TYPE("Bearer ");

    private String value;

    AuthConstants(String value) {
        this.value = value;
    }
}
