package com.login_service.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.Set;


@Entity
@Table(name = "users") // Maps to a table named "users"
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor


public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email; // Primary login identifier

    @Column(nullable = false)
    private String password; // Encrypted password

    @Column(unique = true)
    private String phone; // Optional, used for MFA or recovery

    @Column(nullable = false)
    private String role = "STUDENT"; // Default role is "STUDENT"

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt; // Automatically set when the user is created

    @UpdateTimestamp
    @Column(nullable = false)
    private LocalDateTime modifiedAt; // Automatically updates whenever the user entity is updated
}