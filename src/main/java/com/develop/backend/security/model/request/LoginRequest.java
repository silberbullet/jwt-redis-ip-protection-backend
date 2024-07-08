package com.develop.backend.security.model.request;

import lombok.Data;

@Data
public class LoginRequest {
    private String userId;
    private String password;
}
