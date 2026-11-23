package com.sgchen.security.core.enums;

import lombok.Getter;

@Getter
public enum RequestAsymmetricMode {

    /**
     * RSA 非对称加密混合，秘钥会话模式
     */
    RSA_WITH_SESSION("RSA", "RSA，秘钥会话模式", RequestKeyTransMode.SESSION, 2048),

    /**
     * 非对称加密混合，请求头秘钥模式
     */
    RSA_WITH_HEADER("RSA", "RSA，请求头秘钥模式", RequestKeyTransMode.HEADER, 2048),

    /**
     * ECC 非对称加密混合，秘钥会话模式
     */
    ECDH_WITH_SESSION("ECDH", "ECDH，秘钥会话模式", RequestKeyTransMode.SESSION, 256),

    /**
     * ECC 非对称加密模式
     */
    ECDH_WITH_HEADER("ECDH", "ECDH，请求头秘钥模式", RequestKeyTransMode.HEADER, 256),

    /**
     * ELGAMAL 非对称加密混合，秘钥会话模式
     */
    ELGAMAL_WITH_SESSION("ElGamal", "ELGAMAL，秘钥会话模式", RequestKeyTransMode.SESSION, 256),

    /**
     * ElGamal 非对称加密模式
     */
    ELGAMAL_WITH_HEADER("ElGamal", "ElGamal，请求头秘钥模式", RequestKeyTransMode.HEADER, 256),

    /**
     * SM2 非对称加密混合，秘钥会话模式
     */
    SM2_WITH_SESSION("EC", "SM2，秘钥会话模式", RequestKeyTransMode.SESSION, 256),

    /**
     * SM2 非对称加密模式
     */
    SM2_WITH_HEADER("EC", "SM2，请求头秘钥模式", RequestKeyTransMode.HEADER, 256),

    /**
     * 自定义算法占位符
     */
    CUSTOM_ALGORITHM(null, null, null, null);

    private final String algorithm;
    private final String description;
    private final RequestKeyTransMode keyTransMode;
    private final Integer keySize;

    /**
     * 自定义算法的配置
     */
    private static boolean isCustomAlgorithmConfigured = false;

    RequestAsymmetricMode(String algorithm, String description, RequestKeyTransMode keyTransMode, Integer keySize) {
        this.algorithm = algorithm;
        this.description = description;
        this.keyTransMode = keyTransMode;
        this.keySize = keySize;
    }

    /**
     * 配置自定义算法（仅允许配置一次）
     */
    public static synchronized void configureCustomAlgorithm(String algorithm, String description,
                                                             RequestKeyTransMode keyTransMode, Integer keySize) {
        if (isCustomAlgorithmConfigured) {
            throw new IllegalStateException("自定义算法已配置，无法重复配置");
        }
        if (algorithm == null || description == null || keyTransMode == null || keySize == null) {
            throw new IllegalArgumentException("自定义配置均不可为null");
        }

        // 通过反射修改CUSTOM_ALGORITHM的属性
        try {
            java.lang.reflect.Field algorithmField =
                    SecretAlgorithm.class.getDeclaredField("algorithm");
            java.lang.reflect.Field descriptionField =
                    SecretAlgorithm.class.getDeclaredField("description");
            java.lang.reflect.Field keyTransModeField =
                    SecretAlgorithm.class.getDeclaredField("keyTransMode");
            java.lang.reflect.Field keySizeSizeField =
                    SecretAlgorithm.class.getDeclaredField("keySize");

            algorithmField.setAccessible(true);
            descriptionField.setAccessible(true);
            keyTransModeField.setAccessible(true);
            keySizeSizeField.setAccessible(true);

            algorithmField.set(CUSTOM_ALGORITHM, algorithm);
            descriptionField.set(CUSTOM_ALGORITHM, description);
            keyTransModeField.set(CUSTOM_ALGORITHM, keyTransMode);
            keySizeSizeField.set(CUSTOM_ALGORITHM, keySize);

            isCustomAlgorithmConfigured = true;
        } catch (Exception e) {
            throw new RuntimeException("配置自定义算法失败", e);
        }
    }

    // 根据 code 获取对应的枚举实例
    public static RequestAsymmetricMode getByCode(String code) {
        for (RequestAsymmetricMode mode : values()) {
            if (mode.getAlgorithm().equals(code)) {
                return mode;
            }
        }
        return null;
    }
}