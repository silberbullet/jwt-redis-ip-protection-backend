package com.develop.backend.security.model.vo;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.develop.backend.security.model.req.LoginRequest;
import com.develop.backend.security.model.res.LoginResponse;

import lombok.Getter;

/**
 * <p>
 * 서버 사용자 인증 토큰 클래스
 * AbstractAuthenticationToken 추상 클래스를 구현함으로써 커스텀마이징
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.06.
 */
@Getter
public class AuthenticationToken extends AbstractAuthenticationToken {

    // 인증 요청 데이터
    private LoginRequest loginRequest;
    // 인증 응답 데이터
    private LoginResponse loginResponse;
    // 인증 요청 ip
    private String clientIp;
    // 재발급 대상 여부
    private boolean isReissudTarget;

    /**
     * <p>
     * 인증 미완료 대상
     * </p>
     *
     * @author gyeongwooPark
     * @param LoginRequest loginRequest
     * @param boolean      isReissudTarget
     */
    public AuthenticationToken(LoginRequest loginRequest, String clientIp, boolean isReissudTarget) {

        super(null);
        this.loginRequest = loginRequest;
        this.clientIp = clientIp;
        this.isReissudTarget = isReissudTarget;

        setAuthenticated(false);
    }

    /**
     * <p>
     * 인증 완료 대상
     * </p>
     *
     * @author gyeongwooPark
     * @param LoginRequest loginRequest
     * @param boolean      isReissudTarget
     */
    public AuthenticationToken(LoginResponse loginResponse, String clientIp, boolean isReissudTarget,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.loginResponse = loginResponse;
        this.clientIp = clientIp;
        this.isReissudTarget = isReissudTarget;

        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

}
