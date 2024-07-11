package com.develop.backend.security.provider;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import com.develop.backend.security.model.res.LoginResponse;
import com.develop.backend.security.model.vo.AuthenticationToken;
import com.fasterxml.jackson.core.JsonProcessingException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
        private final RedisTemplate<String, Object> redisTemplate;

        @Value("${properties.jwt.domain}")
        private String domain;
        @Value("${properties.jwt.access-token-cookie.expiration-seconds}")
        private int accessCookieExpiration;

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
                        @Value("${properties.jwt.refresh-token.expiration-seconds}") Long refreshTokenValidateMilliSeconds,
                        RedisTemplate<String, Object> redisTemplate) {

                this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
                this.accessTokenValidateMilliSeconds = accessTokenValidateMilliSeconds * 1000;
                this.refreshTokenValidateMilliSeconds = refreshTokenValidateMilliSeconds * 1000;
                this.redisTemplate = redisTemplate;
        }

        /**
         * JWT AccessToken 생성
         *
         * @author gyeongwooPark
         * @param authentication Authentication
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
         * @author gyeongwooPark
         * @param authentication Authentication
         * @return String
         */
        public String createRefreshToken(AuthenticationToken authenticationToken) {
                // 사용자 ID
                String userId = authenticationToken.getLoginResponse().getUserId();
                // 사용자 IP
                String clientIp = authenticationToken.getClientIp();

                log.info("Refresh Token Created At : "
                                + (new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")).format(new Date(new Date().getTime())));
                log.info("Refresh Token Expired At : " + (new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"))
                                .format(new Date(new Date().getTime() + this.refreshTokenValidateMilliSeconds)));

                return Jwts.builder()
                                .subject(userId)
                                .claim("clientIp", clientIp)
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
         * 
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

        /**
         * JWT Token 검증
         *
         * @author gyeongwooPark
         * @param String token
         * @return boolen
         */
        public boolean validateJwtToken(String token) {
                try {
                        Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
                        return true;
                } catch (MalformedJwtException e) {
                        log.error("Invalid Jwt Token : {}", e.getMessage());
                        throw e;
                } catch (ExpiredJwtException e) {
                        log.error("Expired Jwt Token : {}", e.getMessage());
                        // 토큰 만료 케이스는 토큰 재발급을 위해 false 리턴
                        return false;
                } catch (UnsupportedJwtException e) {
                        log.error("Unsupported Jwt Token : {}", e.getMessage());
                        throw e;
                } catch (IllegalArgumentException e) {
                        log.error("Jwt Token Claims Empty : {}", e.getMessage());
                        throw e;
                } catch (JwtException e) {
                        log.error("Jwt Token Error Message : {}", e.getMessage());
                        log.error("Jwt Token Error Class : {}", e.getClass());
                        throw e;
                }
        }

        /**
         * <p>
         * JWT Token 내 Payload 추출
         * </p>
         *
         * @author gyeongwooPark
         * @param token 토큰
         * @return Claims
         */
        private Claims getPayloadFromJwtToken(String token) {
                Claims claims = null;
                try {
                        claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
                } catch (ExpiredJwtException e) {
                        log.debug("ExpiredJwtException Token");
                        claims = e.getClaims();
                } catch (Exception e) {
                        throw e;
                }
                return claims;
        }

        /**
         * <p>
         * JWT Token 내 사용자 IP (Claim) 추출
         * </p>
         *
         * @author gyeongwooPark
         * @param String token
         * @return String
         */
        public String getUserIpFromJwtToken(String token) {
                Claims claims = this.getPayloadFromJwtToken(token);

                if (ObjectUtils.isEmpty(claims)) {
                        throw new JwtException("JWT Token Payload 필수 항목인 사용자 IP가 존재하지 않습니다.");
                } else {
                        return claims.get("clientIp").toString();
                }
        }

        /**
         * <p>
         * RefreshToken에서 신규 AccessToken 발급
         * </p>
         *
         * @author gyeongwooPark
         * @param String token
         * @return String
         */
        public String getNewAccessToken(String token) {
                Claims claims = this.getPayloadFromJwtToken(token);

                if (ObjectUtils.isEmpty(claims)) {
                        throw new JwtException("JWT Token Payload 가 존재 하지 않습니다.");
                } else {
                        String userId = claims.get("sub").toString();
                        String clientIp = claims.get("clientIp").toString();

                        LoginResponse loginResponse = new LoginResponse();
                        loginResponse.setUserId(userId);

                        AuthenticationToken authenticationToken = new AuthenticationToken(loginResponse, clientIp,
                                        false, null);

                        return this.createAccessToken(authenticationToken);
                }

        }

        /**
         * <p>
         * accessToken 인증 AuthenticationToken 발급
         * </p>
         *
         * @author gyeongwooPark
         * @param String accessToken
         * @return AuthenticationToken
         */
        public AuthenticationToken getAuthenticationToken(String token) {
                Claims claims = this.getPayloadFromJwtToken(token);

                String userId = claims.get("sub").toString();
                String clientIp = claims.get("clientIp").toString();

                LoginResponse loginResponse = new LoginResponse();
                loginResponse.setUserId(userId);

                AuthenticationToken authenticationToken = new AuthenticationToken(loginResponse, clientIp,
                                false, null);

                return authenticationToken;
        }

        /**
         * <p>
         * 토큰 레디스에 저장
         * </p>
         *
         * @author gyeongwooPark
         * @param refreshToken 리프레시 토큰
         * @param accessToken  액세스 토큰
         */
        public void setTokenToRedis(String accessToken, String refreshToken) throws JsonProcessingException {

                redisTemplate.opsForValue().set(
                                accessToken, refreshToken,
                                new Date().getTime() + this.refreshTokenValidateMilliSeconds, TimeUnit.MILLISECONDS);
        }

        /**
         * <p>
         * 해당 AccessToken에 해당 하는 Refresh Token 가져오기
         * </p>
         *
         * @author gyeongwooPark
         * @param accessToken 액세스 토큰
         * @return refreshToken 리프레시 토큰
         */
        public String getRefreshTokenToRedis(String accessToken) throws JsonProcessingException {

                return (String) redisTemplate.opsForValue().get(accessToken);
        }

        /**
         * <p>
         * 해당 AccessToken에 해당 하는 Refresh Token 삭제하기
         * </p>
         *
         * @author gyeongwooPark
         * @param accessToken 액세스 토큰
         */
        public void deleteTokenToRedis(String accessToken) throws JsonProcessingException {
                redisTemplate.delete(accessToken);
        }

        /**
         * <p>
         * accessToken 헤더에 세팅
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

        /**
         * <p>
         * accessToken 헤더에 삭제
         * </p>
         *
         * @author gyeongwooPark
         */
        public HttpServletResponse deleteTokenInCookie(String accessToken, HttpServletResponse response) {

                ResponseCookie accessCookie = ResponseCookie
                                .from("accessToken", accessToken)
                                .domain(domain)
                                .path("/")
                                .httpOnly(false)
                                .maxAge(0)
                                .secure(false)
                                .build();

                response.setHeader("Set-Cookie", accessCookie.toString());

                return response;
        }
}
