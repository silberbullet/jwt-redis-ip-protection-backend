package com.develop.backend.security.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import org.springframework.beans.factory.annotation.Value;

/**
 * <p>
 * CORS 관련 설정
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.05
 */
@Configuration
public class CorsConfig {
    @Value("${properties.front.url}")
    private String frontUrl;

    /**
     * <p>
     * CORS 요청 기본 설정
     * </p>
     *
     * @author gyeongwooPark
     * @return CorsConfigurationSource
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 허용 URL
        configuration.setAllowedOrigins(List.of(frontUrl));
        // 허용 HTTP Method
        configuration.setAllowedMethods(List.of("POST", "GET"));
        // 허용 HTTP Header
        // => Authorization : 클라이언트 인증 정보
        // => Content-type : 요청의 본문 타입 (ex. application/json)
        // => X-Requested-With : 요청이 AJAX 통해 이루어졌는 지 식별
        // => Accept : 클라이언트가 수신 가능한 콘텐츠 유형
        // => Origin : 요청이 시작된 출처
        // => Access-Control-Request-Method : pre-flight 요청에서 실제 요청에서 사용할 HTTP 메소드를 서버에
        // 전달
        // => Access-Control-Request-Headers : pre-flight 요청에서 실제 요청에서 사용할 헤더를 서버에 전달
        configuration.setAllowedHeaders(List.of("Authorization", "Content-type", "X-Requested-With", "Accept", "Origin",
                "Access-Control-Request-Method", "Access-Control-Request-Headers"));
        // 자격 증명(쿠키, 인증 헤더 등)을 포함한 CORS 요청 처리 허용여부
        configuration.setAllowCredentials(true);
        // CORS 설정 URL 패턴 별 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
