package com.example.Auth.domain.user.dao;

import com.example.Auth.domain.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}
