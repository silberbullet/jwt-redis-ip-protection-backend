package com.develop.backend.security.provider;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import com.develop.backend.security.model.res.LoginResponse;
import com.develop.backend.security.model.vo.AuthenticationToken;
import com.develop.backend.security.service.LoginService;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * JSON 기반의 사용자 정보를 인증 처리하기 위한 AuthenticatioinProvider 클래스
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07.
 */
@Component
@RequiredArgsConstructor
public class AuthenticatioinProvider implements AuthenticationManager {

    private final LoginService loginService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof AuthenticationToken)) {
            throw new IllegalArgumentException("This method only accepts AuthenticationToken");
        }

        AuthenticationToken authenticationToken = (AuthenticationToken) authentication;

        // 로그인 서비스 호출 ( DB 조회 )
        LoginResponse loginResponse = loginService.login(authenticationToken);

        // 결과 데이터 미존재 시 예외 처리
        if (ObjectUtils.isEmpty(loginResponse)) {
            throw new AuthenticationServiceException("LoginResponse is Empty");
        }

        return new AuthenticationToken(loginResponse, authenticationToken.getClientIp(),
                authenticationToken.isReissudTarget(), null);
    }

}
