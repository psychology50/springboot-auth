package com.example.Auth.domain.user.api;

import com.example.Auth.domain.user.application.UserAuthService;
import com.example.Auth.domain.user.application.UserSearchService;
import com.example.Auth.domain.user.dto.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Log4j2
public class UserAPI {
    private final UserAuthService userAuthService;
    private final UserSearchService userSearchService;

//    @PostMapping("/login")
//    public ResponseEntity<> login(@RequestBody UserDto userDto) {
//        return ResponseEntity.ok(userAuthService.login(userDto));
//    }
}
