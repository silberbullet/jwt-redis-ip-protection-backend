
package com.develop.backend.security.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * <p>
 * Jwt Token exception 처리
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07.
 */
public class NonIncludedTokenException extends AuthenticationException {

    public NonIncludedTokenException(String msg) {
        super(msg);
    }
}