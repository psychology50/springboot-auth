package com.example.Auth.domain.user.domain;

import com.example.Auth.domain.model.Auditable;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name="USER")
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString(of = {"id", "name", "email", "role"})
public class User extends Auditable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "github_id", nullable = false)
    private Integer githubId;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "bio")
    private String bio;

    @Column(name = "profile_image_url")
    private String profileImageUrl;

    @Column(name = "email")
    private String email;

    @Convert(converter = RoleTypeConverter.class)
    @Column(name = "role", nullable = false)
    private RoleType role;
}
