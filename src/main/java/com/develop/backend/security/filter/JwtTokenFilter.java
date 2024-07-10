package com.develop.backend.security.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.springframework.lang.NonNull;
import org.springframework.lang.NonNullApi;
import org.springframework.web.filter.OncePerRequestFilter;

import com.develop.backend.security.exception.NonIncludedTokenException;
import com.develop.backend.security.provider.JwtTokenProvider;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.MediaType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * JwtTokenFilter 클래스
 * 들어온 AccessToken을 검증 및 핸들링 하는 filter
 * OncePerRequestFilter 확장
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    /**
     * <p>
     * JWT Token 인증 처리
     * </p>
     *
     * @author gyeongwooPark
     * @param request     HttpServletRequest
     * @param response    HttpServletResponse
     * @param filterChain FilterChain
     * @throws ServletException ServletException
     * @throws IOException      IOException
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            // 쿠키 추출
            Optional<Cookie> accessTokenCookie = jwtTokenProvider.getAccessTokenFromCookies(request);

            // 쿠키 존재
            if (accessTokenCookie.isPresent()) {
                // 토큰 추출
                String accessToken = accessTokenCookie.get().getValue();

                // 토큰 유효성 체크
                if (jwtTokenProvider.validateJwtToken(accessToken)) {

                    // 사용자 ip

                    // 토큰 유효시 doFilter 처리
                    filterChain.doFilter(request, response);
                }
                // 만료 시
                else {
                    // Redis에서 RefreshToken 가져오기
                    String refeshToken = jwtTokenProvider.getRefreshTokenToRedis(accessToken);

                    // refreshToken 유효성 검사
                    // refreshToken이 유효시 accessToken 재발급 처리
                    if (jwtTokenProvider.validateJwtToken(refeshToken)) {
                        // To-Do 재발급 처리

                    }
                    // refreshToken 만료 시 재로그인 진행 필요
                    else {

                    }
                }

            }
            // 쿠키 미 존재
            else {
                throw new NonIncludedTokenException("JWT Access Token Not Included");
            }
        } catch (NonIncludedTokenException e) {
            log.error("JwtTokenFilter error");
            e.printStackTrace();
            response.setContentType(MediaType.APPLICATION_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
            response.getWriter().write(e.getMessage());
        }
    }

}