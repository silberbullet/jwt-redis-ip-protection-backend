package com.develop.backend.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Redis 관련 설정
 * Lettuce 사용, redisTemplate 방식.
 * </p>
 * 
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07
 */
@Configuration
@RequiredArgsConstructor
@EnableRedisRepositories
public class RedisConfig {

    @Value("${spring.redis.host}")
    private String redisHost;
    @Value("${spring.redis.port}")
    private int redisPort;

    /**
     * <p>
     * Redis 연결 설정
     * </p>
     *
     * @author gyeongwooPark
     * @return RedisConnectionFactory
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(redisHost, redisPort);
    }

    /**
     * <p>
     * Redis 통신을 위한 restTemplate
     * </p>
     *
     * @author gyeongwooPark
     * @return CorsConfigurationSource
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory());
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new StringRedisSerializer());
        return redisTemplate;
    }
}
