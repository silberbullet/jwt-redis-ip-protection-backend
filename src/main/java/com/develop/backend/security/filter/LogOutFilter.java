package com.develop.backend.security.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.springframework.lang.NonNull;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

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
 * LogOutFilter 클래스
 * OncePerRequestFilter 확장
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07.
 */
@Slf4j
@RequiredArgsConstructor
public class LogOutFilter extends OncePerRequestFilter {

    private final RequestMatcher requestMatcher;
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        // 로그아웃 요청 시
        if (requestMatcher.matches(request)) {
            Optional<Cookie> accessTokenCookie = jwtTokenProvider.getAccessTokenFromCookies(request);
            if (accessTokenCookie.isPresent()) {
                // 토큰 추출
                String accessToken = accessTokenCookie.get().getValue();

                // 레디스에 Access와 RefreshToken 지우기
                jwtTokenProvider.deleteTokenToRedis(accessToken);
                log.info("토큰 삭제 완료");

                // 헤더에 쿠키 지우고 Response 반환
                response = jwtTokenProvider.deleteTokenInCookie(accessToken, response);
                response.setContentType(MediaType.APPLICATION_JSON);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().write("Logout Success!");
                response.getWriter().flush();
                response.getWriter().close();
                log.info("Logout 처리 완료");
            } else {
                response.setContentType(MediaType.APPLICATION_JSON);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Non Include cookie in your header!");
                response.getWriter().flush();
                response.getWriter().close();
            }
        }
        // 아니면 넘기기
        else {
            filterChain.doFilter(request, response);
        }
    }

}
