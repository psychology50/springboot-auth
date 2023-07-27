package com.example.Auth.domain.user.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name="USER")
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User extends Auditable{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "github_id", nullable = false)
    private Integer githubId;

    @Column(name = "bio")
    private String bio;

    @Column(name = "profile_image_url")
    private String profileImageUrl;

    @Column(name = "email")
    private String email;

    @Column(name = "role", nullable = false)
    private RoleType role;
}
