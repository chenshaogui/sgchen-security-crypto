package com.sgchen.security.transfer.config;

import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.config.SgchenSecretProperties;
import com.sgchen.security.core.enums.RequestAsymmetricMode;
import com.sgchen.security.core.enums.RequestKeyTransMode;
import com.sgchen.security.core.enums.RequestSolveMode;
import com.sgchen.security.core.enums.SecretAlgorithm;
import com.sgchen.security.core.exception.DataSecurityException;
import org.apache.commons.codec.binary.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SgchenSecretProperties.class)
public class SecretAutoConfiguration {

    @Autowired
    private SgchenSecretProperties sgchenSecretProperties;

    @Bean
    @ConditionalOnExpression("(" +
            // 请求配置有效：启用且核心属性非空
            "(${csg-security.request.enabled:true} && (" +
            "T(org.springframework.util.StringUtils).hasText('${csg-security.request.secretKey:}') || " +
            "T(org.springframework.util.StringUtils).hasText('${csg-security.request.algorithm:}') " +
            ")) " +
            ")")
    @ConditionalOnMissingBean
    public SecretContext secretContext() {
        // 获取请求参数配置
        SgchenSecretProperties.Request request = sgchenSecretProperties.getRequest();

        if(request!=null && StringUtils.equals(request.getAlgorithm(),"CUSTOM_ALGORITHM")){
            if(request.getCustomAlgorithm()==null){
                throw new DataSecurityException("配置自定义算法，请配置[csg-security.request.customAlgorithm]参数");
            }
            SgchenSecretProperties.CustomAlgorithm customAlgorithm = request.getCustomAlgorithm();
            SecretAlgorithm.configureCustomAlgorithm(customAlgorithm.getAlgorithm(),
                    customAlgorithm.isSkipError(), customAlgorithm.getKeySize(), customAlgorithm.getIvSize());
        }

        if(request!=null && StringUtils.equals(request.getUseAsymmetricMode(),"CUSTOM_ALGORITHM")){
            if(request.getCustomSecretKeyAlgorithm()==null){
                throw new DataSecurityException("配置自定义算法，请配置[csg-security.request.customSecretKeyAlgorithm]参数");
            }
            SgchenSecretProperties.CustomSecretKeyAlgorithm keyAlgorithm = request.getCustomSecretKeyAlgorithm();
            // 配置非对称秘钥的自定义算法
            RequestAsymmetricMode.configureCustomAlgorithm(keyAlgorithm.getAlgorithm(), keyAlgorithm.getDescription(),
                    resolveRequestKeyTransMode(keyAlgorithm.getTransMode()), keyAlgorithm.getKeySize());
        }

        return SecretContext.builder()
                // 请求参数加密key
                .reqSecretKey(request != null ? request.getSecretKey() : null)
                // 请求参数加密IV
                .reqSecretIV(request != null ? request.getSecretIV() : null)
                // 请求参数加密算法（转换为枚举）
                .reqAlgorithm(resolveAlgorithm(request != null ? request.getAlgorithm() : null))
                // 请求数据加密模式（转换为枚举）
                .requestSolveMode(resolveRequestSolveMode(request != null ? request.getTransMode() : null))
                // 非对称加密模式（转换为枚举）
                .requestAsymmetricMode(resolveAsymmetricMode(request != null ? request.getUseAsymmetricMode() : null))
                .clientCode(request != null ? request.getClientCode() : null)
                .build();
    }

    /**
     * 将字符串算法名称转换为SecretAlgorithm枚举
     */
    private SecretAlgorithm resolveAlgorithm(String algorithmName) {
        if (algorithmName == null || algorithmName.isEmpty()) {
            return null;
        }
        for (SecretAlgorithm algorithm : SecretAlgorithm.values()) {
            if (algorithmName.equals(algorithm.getEncryptAlgorithm())) {
                return algorithm;
            }
        }
        // 支持通过枚举名称匹配（如"PKCS7"）
        try {
            return SecretAlgorithm.valueOf(algorithmName);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * 将字符串转换为RequestSolveMode枚举
     */
    private RequestSolveMode resolveRequestSolveMode(String mode) {
        if (mode == null || mode.isEmpty()) {
            return RequestSolveMode.FULL; // 默认全参数模式
        }
        try {
            return RequestSolveMode.valueOf(mode);
        } catch (IllegalArgumentException e) {
            return RequestSolveMode.FULL; // 默认值
        }
    }

    /**
     * 将字符串转换为RequestKeyTransMode枚举
     */
    private RequestKeyTransMode resolveRequestKeyTransMode(String mode) {
        if (mode == null || mode.isEmpty()) {
            return RequestKeyTransMode.HEADER; // 头部请求
        }
        try {
            return RequestKeyTransMode.valueOf(mode);
        } catch (IllegalArgumentException e) {
            return RequestKeyTransMode.HEADER;
        }
    }

    /**
     * 将字符串转换为RequestAsymmetricMode枚举
     */
    private RequestAsymmetricMode resolveAsymmetricMode(String mode) {
        if (mode == null || mode.isEmpty()) {
            return null;
        }
        try {
            return RequestAsymmetricMode.valueOf(mode);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

}