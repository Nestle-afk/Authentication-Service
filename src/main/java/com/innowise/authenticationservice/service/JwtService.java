package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.config.JwtProperties;
import com.innowise.authenticationservice.model.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;

    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(String email, Role role) {
        return generateToken(email, role, jwtProperties.getExpiration());
    }

    public String generateRefreshToken(String email, Role role) {
        return generateToken(email, role, jwtProperties.getRefreshExpiration());
    }

    private String generateToken(String email, Role role, long expirationMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMillis);

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .claim("role", role == null ? null : role.name())
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Role extractRole(String token) {
        try {
            Claims claims = extractAllClaims(token);
            if (claims == null) return null;
            String roleStr = claims.get("role", String.class);
            if (roleStr == null) return null;
            return Role.valueOf(roleStr);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        try {
            Claims claims = extractAllClaims(token);
            return claims == null ? null : claimsResolver.apply(claims);
        } catch (JwtException | IllegalArgumentException ex) {
            return null;
        }
    }

    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException | IllegalArgumentException ex) {
            return null;
        }
    }

    public boolean isTokenValid(String token, String email) {
        final String extractedEmail = extractEmail(token);
        return (extractedEmail.equals(email) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
