package com.example.Auth.domain.user.application;

import com.example.Auth.domain.user.dao.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class UserAuthServiceTest {
    @Autowired
    private UserRepository userRepository;

    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
    }

    @Test @DisplayName("UserAuthService 객체가 생성되는지 확인")
    @Transactional
    void testUserAuthService() {
        UserAuthService userAuthService = new UserAuthService(userRepository);
        assertNotNull(userAuthService);
    }
}