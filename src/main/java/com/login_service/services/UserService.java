package com.login_service.services;

import com.login_service.models.User;
import com.login_service.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);


    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User register(User user) {
        logger.info("Encrypting password for user: {}", user.getEmail());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User savedUser = userRepository.save(user);
        logger.info("User registered successfully: {}", user.getEmail());
        return savedUser;
    }

    public User authenticate(String email, String password) {
        logger.info("Authenticating user with email: {}", email);
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            logger.warn("User not found: {}", email);
            throw new RuntimeException("User not found");
        }

        User user = userOptional.get();
        if (!passwordEncoder.matches(password, user.getPassword())) {
            logger.warn("Invalid credentials for user: {}", email);
            throw new RuntimeException("Invalid credentials");
        }

        logger.info("Authentication successful for user: {}", email);
        return user;
    }
}