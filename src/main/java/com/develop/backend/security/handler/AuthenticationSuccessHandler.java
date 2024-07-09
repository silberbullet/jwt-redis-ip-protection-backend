package com.develop.backend.security.handler;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.develop.backend.security.model.vo.AuthenticationToken;
import com.develop.backend.security.provider.JwtTokenProvider;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * AuthenticationSuccessHandler
 * 로그인 인증 성공 시 콜백 처리하기 위한 클래스
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07.
 */
@Component
@RequiredArgsConstructor
public class AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        AuthenticationToken authenticationToken = (AuthenticationToken) authentication;

        try {
            // 인증 객체 일 시
            if (authenticationToken.isAuthenticated()) {

                // 토큰 발급
                String accessToken = jwtTokenProvider.createAccessToken(authenticationToken);
                String refreshToken = jwtTokenProvider.createRefreshToken(authenticationToken);

                // 기존 토큰이 존재 시
                if (authenticationToken.isReissudTarget()) {
                    // 기존 Redis에 저장 된 Refresh 토큰 제거

                }
                // 기존 토큰이 미존재 시
                else {

                }

            }
        } catch (Exception e) {
        }

    }

}
