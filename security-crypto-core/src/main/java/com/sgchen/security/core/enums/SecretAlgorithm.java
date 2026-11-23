package com.sgchen.security.core.enums;

import lombok.Getter;

@Getter
public enum SecretAlgorithm {

    /**
     * 以下是通用模式，当加解密失败时会返回原始数据
     */
    AES_ECB_PKCS5("AES/ECB/PKCS5Padding", true, 128, 16),

    AES_ECB_PKCS7("AES/ECB/PKCS7Padding", true, 128, 16),

    AES_CBC_PKCS7("AES/CBC/PKCS7Padding", true, 128, 16),

    SM4_ECB_PKCS7("SM4/ECB/PKCS7Padding", true, 128, 16),

    SM4_CBC_PKCS7("SM4/CBC/PKCS7Padding", true, 128, 16),

    /**
     * 以下是严格模式，当加解密失败时抛出异常
     */
    AES_ECB_PKCS5_STRICT("AES/ECB/PKCS5Padding", false, 128, 16),

    AES_ECB_PKCS7_STRICT("AES/ECB/PKCS7Padding", false, 128, 16),

    AES_CBC_PKCS7_STRICT("AES/CBC/PKCS7Padding", false, 128, 16),

    SM4_ECB_PKCS7_STRICT("SM4/ECB/PKCS7Padding", false, 128, 16),

    SM4_CBC_PKCS7_STRICT("SM4/CBC/PKCS7Padding", false, 128, 16),

    /**
     * 自定义算法占位符
     */
    CUSTOM_ALGORITHM(null, null, 128, 16);

    /**
     * 加密算法
     */
    private final String encryptAlgorithm;

    /**
     * 当加解密失败时是否跳过加解密错误数据
     */
    private final Boolean isSkipError;

    private final Integer keySize;

    private final Integer ivSize;

    /**
     * 自定义算法的配置
     */
    private static boolean isCustomAlgorithmConfigured = false;

    SecretAlgorithm(String algorithm, Boolean isSkipError, Integer keySize, Integer ivSize) {
        this.encryptAlgorithm = algorithm;
        this.isSkipError = isSkipError;
        this.keySize = keySize;
        this.ivSize = ivSize;
    }

    /**
     * 配置自定义算法（仅允许配置一次）
     */
    public static synchronized void configureCustomAlgorithm(String algorithm, Boolean isSkipError,
                                                             Integer keySize, Integer ivSize) {
        if (isCustomAlgorithmConfigured) {
            throw new IllegalStateException("自定义算法已配置，无法重复配置");
        }
        if (algorithm == null || isSkipError == null) {
            throw new IllegalArgumentException("算法和是否跳过错误标志均不可为null");
        }

        // 通过反射修改CUSTOM_ALGORITHM的属性
        try {
            java.lang.reflect.Field encryptAlgorithmField =
                    SecretAlgorithm.class.getDeclaredField("encryptAlgorithm");
            java.lang.reflect.Field isSkipErrorField =
                    SecretAlgorithm.class.getDeclaredField("isSkipError");
            java.lang.reflect.Field keySizeField =
                    SecretAlgorithm.class.getDeclaredField("keySize");
            java.lang.reflect.Field ivSizeSizeField =
                    SecretAlgorithm.class.getDeclaredField("ivSize");

            encryptAlgorithmField.setAccessible(true);
            isSkipErrorField.setAccessible(true);

            encryptAlgorithmField.set(CUSTOM_ALGORITHM, algorithm);
            isSkipErrorField.set(CUSTOM_ALGORITHM, isSkipError);
            if (keySize != null) {
                keySizeField.setAccessible(true);
                keySizeField.set(CUSTOM_ALGORITHM, keySize);
            }

            if (ivSize != null) {
                ivSizeSizeField.setAccessible(true);
                ivSizeSizeField.set(CUSTOM_ALGORITHM, ivSize);
            }

            isCustomAlgorithmConfigured = true;
        } catch (Exception e) {
            throw new RuntimeException("配置自定义算法失败", e);
        }
    }

}
