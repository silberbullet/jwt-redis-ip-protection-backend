package com.develop.backend.security.handler;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.develop.backend.security.model.vo.AuthenticationToken;
import com.develop.backend.security.provider.JwtTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.MediaType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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
@RequiredArgsConstructor
@Slf4j
public class AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper;

    @Value("${properties.jwt.domain}")
    private String domain;
    @Value("${properties.jwt.access-token-cookie.expiration-seconds}")
    private int accessCookieExpiration;
    @Value("${properties.jwt.refresh-token-cookie.expiration-seconds}")
    private int refreshCookieExpiration;

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
                    // Redis에 저장 된 Refresh 토큰 제거
                    Optional<Cookie> accessTokenCookie = jwtTokenProvider.getAccessTokenFromCookies(request);
                    String deleteToken = accessTokenCookie.get().getValue();
                    jwtTokenProvider.deleteTokenToRedis(deleteToken);
                }

                // 레디스 Refresh Token 저장
                jwtTokenProvider.setTokenToRedis(accessToken, refreshToken);

                // 쿠키에 토큰 세팅 후 헤더에 추가
                response = setTokenInCookie(accessToken, response);
                response.setContentType(MediaType.APPLICATION_JSON);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.setStatus(HttpServletResponse.SC_OK);

                String body = objectMapper.writeValueAsString(authenticationToken.getLoginResponse());
                response.getWriter().write(body);
            } else {
                response.setContentType(MediaType.APPLICATION_JSON);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("AuthenticationSuccessHandler error");
            }
        } catch (IllegalArgumentException e) {
            log.error("AuthenticationSuccessHandler error");
            e.printStackTrace();
            response.setContentType(MediaType.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST); // 400
            response.getWriter().write("Authentication principal has not allowed");
            response.getWriter().flush();
            response.getWriter().close();
        } catch (Exception e) {
            response.setContentType(MediaType.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR); // 500
            response.getWriter().write("An error occurred during authentication success handling");
            response.getWriter().flush();
            response.getWriter().close();
        }
    }

    /**
     * <p>
     * accessToken와 refreshToken 헤더에 세팅
     * </p>
     *
     * @author gyeongwooPark
     */
    public HttpServletResponse setTokenInCookie(String accessToken, HttpServletResponse response) {

        ResponseCookie accessCookie = ResponseCookie
                .from("accessToken", accessToken)
                .domain(domain)
                .path("/")
                .httpOnly(true)
                .maxAge(accessCookieExpiration)
                .secure(false)
                .build();

        response.setHeader("Set-Cookie", accessCookie.toString());

        return response;
    }

}
