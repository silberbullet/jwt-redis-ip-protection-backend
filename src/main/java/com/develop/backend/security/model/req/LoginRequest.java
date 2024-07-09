package com.develop.backend.security.model.req;

import lombok.Data;

@Data
public class LoginRequest {
    private String userId;
    private String password;
}
