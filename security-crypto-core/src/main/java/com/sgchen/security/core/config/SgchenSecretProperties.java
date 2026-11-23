package com.sgchen.security.core.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author sgchen
 * @date 2025/6/4 9:05
 */
@Data
@ConfigurationProperties(prefix = "csg-security")
public class SgchenSecretProperties {

    /**
     * 请求参数配置（外部类中定义内部类属性）
     */
    private Request request;

    /**
     * 数据加解密配置（外部类中定义内部类属性）
     */
    private DataBase database;

    /**
     * 请求参数配置
     */
    @Data
    public static class Request {

        // 控制请求配置是否启用，默认开启
        private boolean enabled = true;

        /**
         * 请求参数加密的key
         */
        private String secretKey;

        /**
         * 请求参数加密的IV
         */
        private String secretIV;

        /**
         * 请求参数加密算法
         */
        private String algorithm;

        /**
         * 请求的数据加密模式，FULL全部参数加解密，FIELD单个字段加解密
         */
        private String transMode;

        /**
         * 使用非对称模式
         */
        private String useAsymmetricMode;

        /**
         * 平台编码标识
         */
        private String clientCode;

        /**
         * 自定义加密算法
         */
        private CustomAlgorithm customAlgorithm;

        /**
         * 自定义key加密算法
         */
        private CustomSecretKeyAlgorithm customSecretKeyAlgorithm;

    }

    /**
     * 数据加解密
     */
    @Data
    public static class DataBase {
        // 控制数据库配置是否启用，默认开启
        private boolean enabled = true;
        /**
         * 数据库加密key
         */
        private String secretKey;

        /**
         * 数据库加密算法
         */
        private String algorithm;
    }

    /**
     * 自定义加解密算法
     */
    @Data
    public static class CustomAlgorithm {
        /**
         * 加密算法
         */
        private String algorithm;

        /**
         * 当加解密失败时是否跳过加解密错误数据
         */
        private boolean skipError = true;

        private Integer keySize;

        private Integer ivSize;

    }

    /**
     * 自定义非对称算法
     */
    @Data
    public static class CustomSecretKeyAlgorithm {

        private String algorithm;

        private String description;

        private String transMode;

        private Integer keySize;

    }

}