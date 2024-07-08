package com.develop.backend.security.filter;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.develop.backend.security.exception.LoginAttempException;
import com.develop.backend.security.model.request.LoginRequest;
import com.develop.backend.utils.UserInfoUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * AbstractAuthenticationProcessingFilter 추상
 * 클래스를 구현함으로써 커스텀마이징
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.05.
 */
@Slf4j
public class AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    // json 타입의 데이터로만 로그인을 진행한다.
    private static final String CONTENT_TYPE = "application/json";
    // 로그인 요청 데이터 크기 제한 (DDoS 방지)
    private static final int MAX_REQUEST_SIZE = 1024;

    /**
     * 생성자 함수
     * 
     * @author gyoengwooPark
     */
    public AuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        if (!CONTENT_TYPE.equals(request.getContentType())) {
            String message = "Authentication Content-Type not supported: " + request.getContentType();
            throw new LoginAttempException(message);
        }

        if (request.getContentLength() > MAX_REQUEST_SIZE) {
            String message = "Authentication Content-Length not supported: " + request.getContentLength();
            throw new LoginAttempException(message);
        }

        logger.info("로그인 요청 데이터 추출");

        // 로그인 요청 데이터 추출
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

        // Client ip 추출
        String userIp = UserInfoUtil.getClientIp(request);

        // Authentication 객체 생성

        Authentication authentication = this.getAuthenticationManager().authenticate(null);

        throw new UnsupportedOperationException("Unimplemented method 'attemptAuthentication'");
    }

}
