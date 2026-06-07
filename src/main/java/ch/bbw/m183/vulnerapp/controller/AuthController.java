package ch.bbw.m183.vulnerapp.controller;

import ch.bbw.m183.vulnerapp.datamodel.UserEntity;
import ch.bbw.m183.vulnerapp.repository.UserRepository;
import ch.bbw.m183.vulnerapp.security.PasswordHashingService;
import ch.bbw.m183.vulnerapp.security.PasswordValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordHashingService passwordHashingService;
    private final PasswordValidator passwordValidator;

    /**
     * Endpoint to change password for the currently authenticated user.
     * Requires: { "oldPassword": "...", "newPassword": "..." }
     * Returns 400 if validation fails, 200 on success.
     */
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestBody Map<String, String> request,
            java.security.Principal principal) {

        String username = principal.getName();
        String oldPassword = request.get("oldPassword");
        String newPassword = request.get("newPassword");

        if (oldPassword == null || newPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "oldPassword and newPassword are required"));
        }

        // Validate new password against rules
        java.util.List<String> validationErrors = passwordValidator.validate(newPassword);
        if (!validationErrors.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("errors", validationErrors));
        }

        // Fetch user
        UserEntity user = userRepository.findById(username).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
        }

        // Verify old password
        if (!passwordHashingService.verifyPassword(oldPassword, user.getPassword())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "Old password is incorrect"));
        }

        // Hash and save new password
        user.setPassword(passwordHashingService.hashPassword(newPassword));
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }

    /**
     * Endpoint to register a new user (public endpoint).
     * Requires: { "username": "...", "password": "...", "fullname": "..." }
     * Returns 400 if validation fails, 409 if user exists, 201 on success.
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {

        String username = request.get("username");
        String password = request.get("password");
        String fullname = request.get("fullname");

        if (username == null || username.isEmpty() || password == null || fullname == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "username, password, and fullname are required"));
        }

        if (username.length() < 3 || username.length() > 50) {
            return ResponseEntity.badRequest().body(Map.of("error", "username must be 3-50 characters"));
        }

        // Validate password
        java.util.List<String> validationErrors = passwordValidator.validate(password);
        if (!validationErrors.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("errors", validationErrors));
        }

        // Check if user exists
        if (userRepository.findById(username).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "User already exists"));
        }

        // Create user
        UserEntity user = new UserEntity()
                .setUsername(username)
                .setPassword(passwordHashingService.hashPassword(password))
                .setFullname(fullname)
                .setRole("ROLE_USER"); // Default role for regular users

        userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "message", "User registered successfully",
                "username", username,
                "fullname", fullname
        ));
    }

    /**
     * Validate password strength (returns errors if invalid).
     * Endpoint for frontend to check password requirements before submission.
     */
    @PostMapping("/validate-password")
    public ResponseEntity<?> validatePassword(@RequestBody Map<String, String> request) {
        String password = request.get("password");

        if (password == null || password.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "password is required"));
        }

        java.util.List<String> errors = passwordValidator.validate(password);
        if (errors.isEmpty()) {
            return ResponseEntity.ok(Map.of("valid", true));
        } else {
            return ResponseEntity.ok(Map.of("valid", false, "errors", errors));
        }
    }

    /**
     * Admin endpoint to promote a user to ROLE_ADMIN.
     * Only callable by users with ROLE_ADMIN.
     */
    @PostMapping("/promote")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> promoteUser(@RequestBody Map<String, String> request) {
        String username = request.get("username");

        if (username == null || username.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "username is required"));
        }

        UserEntity user = userRepository.findById(username).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
        }

        if ("ROLE_ADMIN".equals(user.getRole())) {
            return ResponseEntity.ok(Map.of("message", "User is already admin", "username", username));
        }

        user.setRole("ROLE_ADMIN");
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "User promoted to admin", "username", username, "role", "ROLE_ADMIN"));
    }

    /**
     * Admin endpoint to demote a user back to ROLE_USER.
     * Only callable by users with ROLE_ADMIN.
     */
    @PostMapping("/demote")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> demoteUser(@RequestBody Map<String, String> request) {
        String username = request.get("username");

        if (username == null || username.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "username is required"));
        }

        UserEntity user = userRepository.findById(username).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
        }

        if ("ROLE_USER".equals(user.getRole())) {
            return ResponseEntity.ok(Map.of("message", "User is already regular user", "username", username));
        }

        user.setRole("ROLE_USER");
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "User demoted to regular user", "username", username, "role", "ROLE_USER"));
    }
}




