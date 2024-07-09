package com.develop.backend.security.service;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import com.develop.backend.security.model.res.LoginResponse;
import com.develop.backend.security.model.vo.AuthenticationToken;

/**
 * <p>
 * 인증 요청 객체를 통해서 인증된 사용자 인지 조회 하기 위한 login 클래스
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07.
 */
@Service
public class LoginServiceImpl implements LoginService {

    // 테스트 userId
    private final String USER_ID = "admin";
    // 테스트 password
    private final String PASSWORD = "12345";

    @Override
    public LoginResponse login(AuthenticationToken authenticationToken) throws AuthenticationException {

        LoginResponse loginResponse = new LoginResponse();
        // 로그인 성공
        if (USER_ID.equals(authenticationToken.getLoginRequest().getUserId()) &&
                PASSWORD.equals(authenticationToken.getLoginRequest().getPassword())) {
            loginResponse.setUserId(USER_ID);
        }
        // 로그인 실패
        else {
            throw new AuthenticationServiceException("사용자 인증에 실패 하였습니다.");
        }

        return loginResponse;
    }

}
