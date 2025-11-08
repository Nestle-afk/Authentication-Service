package com.innowise.authenticationservice.dto;

import com.innowise.authenticationservice.model.Role;
import lombok.Data;

@Data
public class AuthUserDto {
    private String email;
    private String password;
    private Role role;
}
