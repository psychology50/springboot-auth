package com.example.Auth.domain.user.application;

import com.example.Auth.domain.user.dao.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserSearchService {
    private final UserRepository userRepository;
}
