package com.develop.backend.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.develop.backend.fw.master.CMMaster;
import com.develop.backend.security.model.vo.AuthenticationToken;

import io.jsonwebtoken.lang.Objects;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * 사용자 정보 CMMaster 사전 세팅
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07
 */
@Aspect
@Component
@Slf4j
public class UserAspect {

    @Pointcut("execution(* com.develop.backend.api.controller.*.*(..))")
    private void inWebLayer() {
    }

    @Before("inWebLayer()")
    public void setUserInfo(JoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();

        for (Object arg : args) {
            if (arg instanceof CMMaster) {
                // 사용자 정보 세팅

                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (!Objects.isEmpty(authentication)) {
                    AuthenticationToken authenticationToken = (AuthenticationToken) authentication;
                    ((CMMaster) arg).setUserId((String) authenticationToken.getPrincipal());
                    ((CMMaster) arg).setUserIp(authenticationToken.getClientIp());
                    log.info("접속한 사용자 정보----------------------------------");
                    log.info("사용자 ID : " + (String) authenticationToken.getPrincipal());
                    log.info("사용자 IP : " + authenticationToken.getClientIp());
                }
            }
        }
    }
}
