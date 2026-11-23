package com.sgchen.security.core.config;

import com.sgchen.security.core.enums.RequestAsymmetricMode;
import com.sgchen.security.core.enums.RequestSolveMode;
import com.sgchen.security.core.enums.SecretAlgorithm;
import lombok.Builder;
import lombok.Data;

/**
 * @author sgchen
 * @date 2025/6/4 9:05
 */
@Data
@Builder
public class SecretContext {

    /**
     * 请求参数加密的key
     */
    private String reqSecretKey;

    /**
     * 请求参数加密算法
     */
    private SecretAlgorithm reqAlgorithm;

    /**
     * 请求的数据加密模式，FULL全部参数加解密，FIELD单个字段加解密
     */
    @Builder.Default
    private RequestSolveMode requestSolveMode = RequestSolveMode.FULL;

    /**
     * 请求参数加密的IV
     */
    private String reqSecretIV;

    /**
     * 请求使用非对称模式
     */
    private RequestAsymmetricMode requestAsymmetricMode;

    /**
     * 数据库加密key
     */
    private String dbSecretKey;

    /**
     * 数据库加密算法
     */
    private SecretAlgorithm dbAlgorithm;

    /**
     * 平台编码标识
     */
    private String clientCode;
}