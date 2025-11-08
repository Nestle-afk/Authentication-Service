package com.innowise.authenticationservice.controller;

import com.innowise.authenticationservice.dto.*;
import com.innowise.authenticationservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody AuthUserDto dto) {
        authService.register(dto);
        return ResponseEntity.ok("User registered successfully");
    }


    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        TokenResponse tokens = authService.authenticateAndGetTokens(request);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestBody RefreshTokenRequest request) {
        TokenResponse tokens = authService.refresh(request.getRefreshToken());
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validate(@RequestBody ValidateTokenRequest request) {
        boolean isValid = authService.validateAccessToken(request.getToken());
        return ResponseEntity.ok(isValid);
    }

}

