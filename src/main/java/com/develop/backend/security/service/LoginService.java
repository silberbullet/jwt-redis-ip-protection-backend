package com.develop.backend.security.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.develop.backend.security.model.res.LoginResponse;
import com.develop.backend.security.model.vo.AuthenticationToken;

/**
 * <p>
 * 인증 요청 객체를 통해서 인증된 사용자 인지 조회 하기 위한 login Interface
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07.
 */
public interface LoginService {

    /**
     * login 처리
     * 
     * @param AuthenticationToken authenticationToken
     * @return LoginResponse (로그인한 사용자 정보)
     * @author gyeongwooPark
     */
    LoginResponse login(AuthenticationToken authenticationToken) throws AuthenticationException;
}
