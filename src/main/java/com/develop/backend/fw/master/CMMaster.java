package com.develop.backend.fw.master;

import lombok.Data;

/**
 * <p>
 * 비즈니스 처리 시 공통으로 확장 받아야 하는 vo 객체
 * DB 메타데이터로 등록 될 데이터
 * </p>
 *
 * @author gyeongwooPark
 * @version 1.0
 * @since 2024.07
 */
@Data
public class CMMaster {

    // 사용자 ID
    private String userId;
    // 사용자 IP
    private String userIp;
}
