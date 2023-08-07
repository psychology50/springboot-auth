package com.example.Auth.domain.user.dto;

import com.example.Auth.domain.user.domain.RoleType;
import lombok.Getter;

@Getter
public class UserAuthenticateDto {
    private Long id;

    private UserAuthenticateDto(Long id) {
        this.id = id;
    }

    public static UserAuthenticateDto of(Long id) {
        return new UserAuthenticateDto(id);
    }

    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UserAuthenticateDto(");
        sb.append("id=").append(id);
        sb.append(")");
        return sb.toString();
    }
}
