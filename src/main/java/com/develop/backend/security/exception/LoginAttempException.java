package com.develop.backend.security.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * <p>
 * 로그인 관련 exception 처리
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.05.
 */
public class LoginAttempException extends AuthenticationException {

    public LoginAttempException(String msg) {
        super(msg);
    }
}
