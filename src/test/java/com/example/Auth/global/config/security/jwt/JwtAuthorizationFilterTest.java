package com.example.Auth.global.config.security.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class JwtAuthorizationFilterTest {
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext context;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    public void testValidToken() throws Exception {

    }

//    @Test
//    public void testInvalidToken() throws Exception {
//        String invalidToken = "invalid_token";
//
//        mockMvc.perform(get("/api/v1/test/protected")
//                .header(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + invalidToken))
//                .andExpect(status().isUnauthorized())
//                .andDo(print());
//    }
//
//    @Test
//    public void testNoToken() throws Exception {
//        mockMvc.perform(get("/api/v1/test/protected"))
//                .andExpect(status().isUnauthorized())
//                .andDo(print());
//
//    }
}