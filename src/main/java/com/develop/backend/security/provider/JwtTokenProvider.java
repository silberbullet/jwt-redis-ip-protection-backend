package com.develop.backend.security.provider;

import java.util.Arrays;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

/**
 * <p>
 * JWT Token 생성 및 검증 Provider
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.05.
 */
@Component
public class JwtTokenProvider {

    /**
     * <p>
     * Cookie 내 JWT Access Token 추출
     * </p>
     *
     * @author gyeongwooPark
     * @param request HttpServletRequest
     * @return String
     */
    public Optional<Cookie> getAccessTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (!ObjectUtils.isEmpty(cookies)) {
            return Arrays.stream(cookies)
                    .filter(s -> StringUtils.equals(s.getName(), "accessToken"))
                    .findFirst();
        }

        return Optional.empty();
    }

    /**
     * <p>
     * Cookie 내 JWT Refresh Token 추출
     * </p>
     *
     * @author gyeongwooPark
     * @param request HttpServletRequest
     * @return String
     */
    public Optional<Cookie> getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (!ObjectUtils.isEmpty(cookies)) {
            return Arrays.stream(cookies)
                    .filter(s -> StringUtils.equals(s.getName(), "refreshToken"))
                    .findFirst();
        }

        return Optional.empty();
    }

}
