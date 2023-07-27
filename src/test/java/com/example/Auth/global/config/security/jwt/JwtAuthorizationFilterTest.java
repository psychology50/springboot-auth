package com.example.Auth.global.config.security.jwt;

import com.example.Auth.domain.user.domain.RoleType;
import com.example.Auth.domain.user.domain.User;
import com.example.Auth.domain.user.dto.UserAuthenticateDto;
import com.example.Auth.domain.user.dto.UserDto;
import jakarta.servlet.FilterChain;
import org.aspectj.lang.annotation.Before;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class JwtAuthorizationFilterTest {
    private MockMvc mockMvc;

    @InjectMocks
    private JwtAuthorizationFilter jwtAuthorizationFilter;

    @Mock
    private FilterChain filterChain;

    @Before("setup")
    public void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup().build();
    }

    @Test
    public void testValidToken() throws Exception {
        User user = User.builder()
                .id(1L)
                .name("John Doe")
                .email("a@a.com")
                .role(RoleType.USER)
                .build();
        UserAuthenticateDto userDto = UserAuthenticateDto.of(user.getId(), user.getName());
        String token = JwtTokenProvider.generateAccessToken(userDto);

        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/api/v1/users/login")
                .header(AuthConstants.AUTH_HEADER.getValue(), AuthConstants.TOKEN_TYPE + token);

        mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(content().string("Protected Resource"))
                .andDo(print());
    }

    @Test
    public void testInvalidToken() throws Exception {
        String invalidToken = "invalid_token";

        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/api/v1/users/login")
                .header(AuthConstants.AUTH_HEADER.getValue(), AuthConstants.TOKEN_TYPE + invalidToken);

        mockMvc.perform(requestBuilder)
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @Test
    public void testNoToken() throws Exception {
        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/api/v1/users/login");

        mockMvc.perform(requestBuilder)
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @Test
    public void testOptionRequest() throws Exception {
        // OPTIONS 메서드 요청
        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .options("/api/v1/users/login");

        mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(content().string("Option Request"))
                .andDo(print());
    }

    @Test
    public void testTokenValidationException() throws Exception {
        String invalidToken = "invalid_token";

        MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders
                .get("/api/v1/users/login")
                .header(AuthConstants.AUTH_HEADER.getValue(), AuthConstants.TOKEN_TYPE + invalidToken);

//        Mockito.doThrow(new RuntimeException("Invalid Token")).when(jwtAuthorizationFilter).isJwtValid(invalidToken);

        mockMvc.perform(requestBuilder)
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("Token is invalid")))
                .andDo(print());
    }
}