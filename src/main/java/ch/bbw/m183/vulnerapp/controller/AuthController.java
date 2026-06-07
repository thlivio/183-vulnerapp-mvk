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

    private final PasswordValidator passwordValidator;


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



}




