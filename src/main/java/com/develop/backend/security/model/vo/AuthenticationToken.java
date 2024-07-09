package com.develop.backend.security.model.vo;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.develop.backend.security.model.request.LoginRequest;

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

    public AuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);

        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getCredentials'");
    }

    @Override
    public Object getPrincipal() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getPrincipal'");
    }

}
