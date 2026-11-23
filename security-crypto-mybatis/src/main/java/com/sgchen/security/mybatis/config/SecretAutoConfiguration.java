package com.sgchen.security.mybatis.config;

import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.config.SgchenSecretProperties;
import com.sgchen.security.core.enums.SecretAlgorithm;
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
            "(${csg-security.database.enabled:true} && (" +
            "T(org.springframework.util.StringUtils).hasText('${csg-security.database.secretKey:}') || " +
            "T(org.springframework.util.StringUtils).hasText('${csg-security.database.algorithm:}')" +
            "))" +
            ")")
    @ConditionalOnMissingBean
    public SecretContext secretContext() {
        // 获取数据库加密配置
        SgchenSecretProperties.DataBase dbSecret = sgchenSecretProperties.getDatabase();
        return SecretContext.builder()
                .dbSecretKey(dbSecret != null ? dbSecret.getSecretKey() : null)
                .dbAlgorithm(resolveAlgorithm(dbSecret != null ? dbSecret.getAlgorithm() : null))
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
        try {
            return SecretAlgorithm.valueOf(algorithmName);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

}