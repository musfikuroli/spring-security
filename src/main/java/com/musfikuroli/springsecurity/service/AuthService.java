package com.musfikuroli.springsecurity.service;

import com.musfikuroli.springsecurity.config.JwtUtils;
import com.musfikuroli.springsecurity.dto.AuthRequest;
import com.musfikuroli.springsecurity.dto.AuthResponse;
import com.musfikuroli.springsecurity.dto.RefreshTokenRequest;
import com.musfikuroli.springsecurity.model.Role;
import com.musfikuroli.springsecurity.model.User;
import com.musfikuroli.springsecurity.repository.RoleRepository;
import com.musfikuroli.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public AuthResponse register(AuthRequest request, String roleName) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Username already taken");
        }
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Collections.singleton(role))
                .build();
        userRepository.save(user);

        return login(new AuthRequest(request.getUsername(), request.getPassword()));
    }

    public AuthResponse login(AuthRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        // If successful:
        org.springframework.security.core.userdetails.User principal =
                (org.springframework.security.core.userdetails.User) auth.getPrincipal();

        String jwtToken = jwtUtils.generateToken(principal);
        String refreshToken = jwtUtils.generateRefreshToken(principal);

        return AuthResponse.builder()
                .username(principal.getUsername())
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthResponse refreshToken(RefreshTokenRequest request) {
        // Validate refresh token
        String refreshToken = request.getRefreshToken();
        String username = jwtUtils.extractUsername(refreshToken);

        // Optionally ensure user is still active
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Check if refresh token is valid
        org.springframework.security.core.userdetails.User userDetails =
                new org.springframework.security.core.userdetails.User(
                        user.getUsername(),
                        user.getPassword(),
                        user.getRoles().stream().map(role ->
                            new org.springframework.security.core.authority.SimpleGrantedAuthority(role.getName())
                        ).toList()
                );

        if (!jwtUtils.isTokenValid(refreshToken, userDetails)) {
            throw new RuntimeException("Invalid refresh token");
        }

        // Generate new tokens
        String accessToken = jwtUtils.generateToken(userDetails);
        String newRefreshToken = jwtUtils.generateRefreshToken(userDetails);

        return AuthResponse.builder()
                .username(userDetails.getUsername())
                .accessToken(accessToken)
                .refreshToken(newRefreshToken)
                .build();
    }
}
