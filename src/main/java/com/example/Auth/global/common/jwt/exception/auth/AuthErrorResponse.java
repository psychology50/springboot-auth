package com.example.Auth.global.common.jwt.exception.auth;

public record AuthErrorResponse(String code, String message) {
    @Override public String toString() {
        return String.format("AuthErrorResponse(code=%s, message=%s)", code, message);
    }
}