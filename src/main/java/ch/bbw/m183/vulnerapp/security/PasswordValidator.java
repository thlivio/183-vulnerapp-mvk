package ch.bbw.m183.vulnerapp.security;

import lombok.Getter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;


@Service
public class PasswordValidator {

    public static final int MIN_LENGTH = 8;
    public static final String SPECIAL_CHARS = "!@#$%^&*";


    public List<String> validate(String password) {
        List<String> errors = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            errors.add("Password cannot be empty");
            return errors;
        }

        if (password.length() < MIN_LENGTH) {
            errors.add("Password must be at least " + MIN_LENGTH + " characters long");
        }

        if (!password.matches(".*[A-Z].*")) {
            errors.add("Password must contain at least one uppercase letter (A-Z)");
        }

        if (!password.matches(".*[a-z].*")) {
            errors.add("Password must contain at least one lowercase letter (a-z)");
        }

        if (!password.matches(".*\\d.*")) {
            errors.add("Password must contain at least one digit (0-9)");
        }

        if (!password.matches(".*[" + java.util.regex.Pattern.quote(SPECIAL_CHARS) + "].*")) {
            errors.add("Password must contain at least one special character: " + SPECIAL_CHARS);
        }

        return errors;
    }

    /**
     * Check if password is valid (returns true if no errors).
     */
    public boolean isValid(String password) {
        return validate(password).isEmpty();
    }

    /**
     * Get validation result as a single exception message (comma-separated).
     * Throws PasswordValidationException if invalid, does nothing if valid.
     */
    public void validateOrThrow(String password) throws PasswordValidationException {
        List<String> errors = validate(password);
        if (!errors.isEmpty()) {
            throw new PasswordValidationException(String.join("; ", errors));
        }
    }

    /**
     * Exception thrown when password validation fails.
     */
    @Getter
    public static class PasswordValidationException extends Exception {
        private final List<String> errors;

        public PasswordValidationException(String message) {
            super(message);
            this.errors = List.of(message.split("; "));
        }

        public PasswordValidationException(List<String> errors) {
            super(String.join("; ", errors));
            this.errors = errors;
        }
    }
}

