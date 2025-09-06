package com.example.Spring.security._JWT.controller;

import com.example.Spring.security._JWT.dto.JwtResponse;
import com.example.Spring.security._JWT.dto.LoginRequest;
import com.example.Spring.security._JWT.dto.RefreshTokenRequest;
import com.example.Spring.security._JWT.dto.UserRegistrationDto;
import com.example.Spring.security._JWT.service.AuthService;
import com.example.Spring.security._JWT.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final UserService userService;


    @PostMapping("/login")
    public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                                        HttpServletRequest request) {
        String clientIP = getClientIP(request);
        JwtResponse response = authService.authenticateUser(loginRequest.getUsername(), loginRequest.getPassword(), clientIP);
        log.info("User {} logged in from IP {}", loginRequest.getUsername(), clientIP);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshRequest) {
        JwtResponse response = authService.refreshToken(refreshRequest.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest refreshRequest) {
        authService.logout(refreshRequest.getRefreshToken());
        log.info("Logout request processed");
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto registrationDto, BindingResult result) {
        if (result.hasErrors()) {
            Map<String, String> errors = result.getFieldErrors().stream()
                    .collect(Collectors.toMap(FieldError::getField, FieldError::getDefaultMessage));
            return ResponseEntity.badRequest().body(errors);
        }

        if (userService.existsByUsername(registrationDto.getUsername())) {
            return ResponseEntity.badRequest().body(Map.of("username", "Пользователь с таким именем уже существует"));
        }

        UserRegistrationDto response = userService.registerUser(registrationDto);
        return ResponseEntity.ok(Map.of("message", "Регистрация прошла успешно", "user", response));
    }

}

