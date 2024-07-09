package com.develop.backend.security.provider;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import com.develop.backend.security.model.vo.AuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * JWT Token 생성 및 검증 Provider
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.05.
 */
@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey key;
    private final Long accessTokenValidateMilliSeconds;
    private final Long refreshTokenValidateMilliSeconds;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * <p>
     * JwtTokenProvider 생성자
     * </p>
     *
     * @author gyeongwooPark
     * @param secretKey                        시크릿 키
     * @param accessTokenValidateMilliSeconds  액세스 토큰 유효 시간(초)
     * @param refreshTokenValidateMilliSeconds 리프레시 토큰 유효 시간(초)
     */
    public JwtTokenProvider(@Value("${properties.jwt.secret-key}") String secretKey,
            @Value("${properties.jwt.access-token.expiration-seconds}") Long accessTokenValidateMilliSeconds,
            @Value("${properties.jwt.refresh-token.expiration-seconds}") Long refreshTokenValidateMilliSeconds) {

        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
        this.accessTokenValidateMilliSeconds = accessTokenValidateMilliSeconds * 1000;
        this.refreshTokenValidateMilliSeconds = refreshTokenValidateMilliSeconds * 1000;
    }

    /**
     * JWT AccessToken 생성
     *
     * @author jinseokJang
     * @param authentication Authentication
     * @param userIp         사용자 Ip
     * @return String
     */
    public String createAccessToken(AuthenticationToken authenticationToken) {
        // 사용자 ID
        String userId = authenticationToken.getLoginResponse().getUserId();
        // 사용자 IP
        String clientIp = authenticationToken.getClientIp();

        log.info("Access Token Created At : "
                + (new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")).format(new Date(new Date().getTime())));
        log.info("Access Token Expired At : " + (new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"))
                .format(new Date(new Date().getTime() + this.accessTokenValidateMilliSeconds)));

        return Jwts.builder()
                .subject(userId)
                .claim("clientIp", clientIp)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + this.accessTokenValidateMilliSeconds))
                .signWith(key)
                .compact();
    }

    /**
     * JWT RefreshToken 생성
     *
     * @author jinseokJang
     * @param authentication Authentication
     * @param userIp         사용자 Ip
     * @return String
     */
    public String createRefreshToken(AuthenticationToken authenticationToken) {
        // 사용자 ID
        String userId = authenticationToken.getLoginResponse().getUserId();
        // 사용자 IP
        String clientIp = authenticationToken.getClientIp();
        // Redis 키
        String redisKey = UUID.randomUUID().toString();

        log.info("Refresh Token Created At : "
                + (new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")).format(new Date(new Date().getTime())));
        log.info("Refresh Token Expired At : " + (new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"))
                .format(new Date(new Date().getTime() + this.refreshTokenValidateMilliSeconds)));

        return Jwts.builder()
                .subject(userId)
                .claim("clientIp", clientIp)
                .claim("redisKey", redisKey)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + this.refreshTokenValidateMilliSeconds))
                .signWith(key)
                .compact();
    }

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
