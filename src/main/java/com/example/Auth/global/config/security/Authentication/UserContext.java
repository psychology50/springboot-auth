package com.example.Auth.global.config.security.Authentication;

import com.example.Auth.domain.user.domain.User;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UserContext extends org.springframework.security.core.userdetails.User {
    private final User user;

    public UserContext(User user, Collection<? extends GrantedAuthority> authorities) {
        super(user.getName(), user.getPassword(), authorities);
        this.user = user;
    }

    User getUser() {
        return user;
    }
}
