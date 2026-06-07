package ch.bbw.m183.vulnerapp.security;

import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Authentication filter that accepts JSON body {"username":"...","password":"..."}
 * and delegates to the AuthenticationManager (so sessions are handled by Spring Security).
 */
public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper;

    public JsonUsernamePasswordAuthenticationFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("json")) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, String> creds = objectMapper.readValue(request.getInputStream(), Map.class);
                String username = creds.getOrDefault("username", "").trim();
                String password = creds.getOrDefault("password", "");
                UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
                setDetails(request, authRequest);
                return this.getAuthenticationManager().authenticate(authRequest);
            } catch (IOException e) {
                throw new AuthenticationServiceException("Invalid JSON authentication request", e);
            }
        }
        return super.attemptAuthentication(request, response);
    }
}



