package com.develop.backend.security.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * <p>
 * Redis 토큰 검증 예외 처리
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07.
 */
public class RedisValidateException extends AuthenticationException {

    public RedisValidateException(String msg) {
        super(msg);
    }

}
