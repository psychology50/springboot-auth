package com.example.Auth.global.config.properties;

import com.example.Auth.domain.user.application.UserAuthService;
import com.example.Auth.domain.user.application.UserSearchService;
import com.example.Auth.domain.user.dao.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class SpringConfig {
    private final UserRepository userRepository;

    @Bean
    public UserSearchService userSearch() {
        return new UserSearchService(userRepository);
    }
    @Bean
    public UserAuthService userAuth() {
        return new UserAuthService(userRepository);
    }

}
