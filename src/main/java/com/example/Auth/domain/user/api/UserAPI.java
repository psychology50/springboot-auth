package com.example.Auth.domain.user.api;

import com.example.Auth.domain.user.application.UserAuthService;
import com.example.Auth.domain.user.application.UserSearchService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserAPI {
    private final UserAuthService userAuthService;
    private final UserSearchService userSearchService;
}
