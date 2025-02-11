package com.musfikuroli.springsecurity.controller;

import com.musfikuroli.springsecurity.dto.AuthRequest;
import com.musfikuroli.springsecurity.dto.AuthResponse;
import com.musfikuroli.springsecurity.dto.RefreshTokenRequest;
import com.musfikuroli.springsecurity.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @RequestBody AuthRequest request,
            @RequestParam(defaultValue = "ROLE_USER") String role // e.g., ROLE_USER, ROLE_MANAGER, ROLE_ADMIN
    ) {
        AuthResponse response = authService.register(request, role);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }
}
