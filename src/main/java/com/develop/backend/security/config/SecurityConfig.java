package com.develop.backend.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.develop.backend.security.filter.AuthenticationFilter;
import com.develop.backend.security.filter.JwtTokenFilter;
import com.develop.backend.security.handler.AuthenticationFailHandler;
import com.develop.backend.security.handler.AuthenticationSuccessHandler;
import com.develop.backend.security.provider.JwtTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Spring Security 설정 클래스
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.05
 */
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final CorsConfig corsConfig;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    @Value("${properties.login.url}")
    private String loginUrl;

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new AuthenticationSuccessHandler(jwtTokenProvider, new ObjectMapper());
    }

    @Bean
    public AuthenticationFailHandler authenticationFailHandler() {
        return new AuthenticationFailHandler();
    }

    /**
     * <p>
     * AbstractAuthenticationProcessingFilter 상속체 Bean 등록
     * </p>
     * 
     * @author gyeongwooPark
     * @return AuthenticationFilter
     */
    @Bean
    public AuthenticationFilter authenticationFilter() {
        RequestMatcher permitUrlMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(loginUrl, HttpMethod.POST.name()));

        AuthenticationFilter authenticationFilter = new AuthenticationFilter(permitUrlMatcher, jwtTokenProvider);
        authenticationFilter.setAuthenticationManager(authenticationManager);
        authenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        authenticationFilter.setAuthenticationFailureHandler(authenticationFailHandler());

        return authenticationFilter;
    }

    /**
     * <p>
     * JwtFilter 등록
     * </p>
     * 
     * @author gyeongwooPark
     * @return JwtFilter
     */
    @Bean
    public JwtTokenFilter jwtTokenFilter() {
        return new JwtTokenFilter(jwtTokenProvider);
    }

    /**
     * <p>
     * Security 기본 설정
     * </p>
     * 
     * @author gyeongwooPark
     * @return SecurityFilterChain
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // => jwt 토큰 방식 사용으로 인해 비활성화 처리
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                // CORS 설정
                .cors(cors -> corsConfig.corsConfigurationSource())
                // 세션 관리 설정
                // => jwt 토큰 방식은 stateless 설정, 세션 생성 방지
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // HTTP 요청 관리
                .authorizeHttpRequests(author -> author
                        // 특정 엔드포인트 접근 허용 처리
                        .requestMatchers("/api/login/**").permitAll()
                        // 그 외 모든 요청은 인증 필수 (jwt 토큰 인증)
                        .anyRequest().authenticated())
                .addFilterAfter(jwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(authenticationFilter(), JwtTokenFilter.class);

        return http.build();
    }

}
