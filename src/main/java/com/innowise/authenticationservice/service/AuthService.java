package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.dto.AuthUserDto;
import com.innowise.authenticationservice.dto.LoginRequest;
import com.innowise.authenticationservice.dto.TokenResponse;
import com.innowise.authenticationservice.model.AuthUser;
import com.innowise.authenticationservice.model.Role;
import com.innowise.authenticationservice.repository.AuthUserRepository;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthUserRepository authUserRepository;
    private final PasswordService passwordService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public void register(AuthUserDto dto) {
        if (authUserRepository.existsByEmail(dto.getEmail())) {
            throw new IllegalArgumentException("User with email already exists");
        }
        AuthUser user = new AuthUser();
        user.setEmail(dto.getEmail());
        user.setPassword(passwordService.hash(dto.getPassword()));
        user.setRole(dto.getRole() == null ? Role.USER : dto.getRole());
        authUserRepository.save(user);
    }

    public TokenResponse authenticateAndGetTokens(LoginRequest loginRequest) {
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(),loginRequest.getPassword()));
        Optional<AuthUser> userOpt = authUserRepository.findByEmail(loginRequest.getEmail());
        AuthUser user = userOpt.orElseThrow(() -> new IllegalStateException("User not found after authentication"));
        String access = jwtService.generateAccessToken(user.getEmail(), user.getRole());
        String refresh = jwtService.generateRefreshToken(user.getEmail(), user.getRole());
        return new TokenResponse(access, refresh);
    }

    public TokenResponse refresh(String refreshToken) {
        String email = jwtService.extractEmail(refreshToken);
        if (email == null || !jwtService.isTokenValid(refreshToken, email)) {
            throw new JwtException("Invalid refresh token");
        }
        AuthUser user = authUserRepository.findByEmail(email).orElseThrow(() -> new IllegalStateException("User not found"));
        String newAccess = jwtService.generateAccessToken(user.getEmail(), user.getRole());
        String newRefresh = jwtService.generateRefreshToken(user.getEmail(), user.getRole());
        return new TokenResponse(newAccess, newRefresh);
    }

    public boolean validateAccessToken(String token) {
        String email = jwtService.extractEmail(token);
        if (email == null) return false;
        return jwtService.isTokenValid(token, email);
    }
}

