package com.sgchen.security.core.util;


import com.sgchen.security.core.enums.RequestAsymmetricMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * 非对称工具类
 */
public class CryptoAsymmetricUtil {

    private CryptoAsymmetricUtil() {
    }

    private static final Logger logger = LoggerFactory.getLogger(CryptoAsymmetricUtil.class);

    /**
     * 生成Asymmetric密钥对
     *
     * @return KeyPair
     */
    public static KeyPair generateAsymmetricKeyPair(RequestAsymmetricMode asymmetricMode) {
        try {
            return CryptoAsymmetricCustomUtil.generateKeyPair(asymmetricMode.getAlgorithm(), asymmetricMode.getKeySize());
        } catch (Exception e) {
            throw new SecurityException("生成" + asymmetricMode.getAlgorithm() + "密钥对失败");
        }
    }


    /**
     * 公钥加密数据
     *
     * @param plainText 加密内容
     * @param publicKey 公钥
     * @return 返回数据
     */
    public static String encryptWithPublicKey(String plainText, PublicKey publicKey,
                                              RequestAsymmetricMode asymmetricMode) {
        try {
            byte[] encryptedBytes = CryptoAsymmetricCustomUtil.encrypt(asymmetricMode.getAlgorithm(), publicKey, plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new SecurityException(asymmetricMode.getAlgorithm() + "加密失败");
        }
    }

    /**
     * 私钥解密数据
     *
     * @param encryptedText 解密字符串
     * @param privateKey    私钥
     * @return 解密后数据
     */
    public static String decryptWithPrivateKey(String encryptedText, PrivateKey privateKey,
                                               RequestAsymmetricMode asymmetricMode) {
        try {
            byte[] decryptedBytes = CryptoAsymmetricCustomUtil.decrypt(asymmetricMode.getAlgorithm(), privateKey, Base64.getDecoder().decode(encryptedText));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecurityException(asymmetricMode.getAlgorithm() + "解密失败", e);
        }
    }

    /**
     * 公钥字符串还原
     *
     * @param publicKeyStr 公钥字符串
     * @return 公钥
     */
    public static PublicKey restorePublicKey(String publicKeyStr, RequestAsymmetricMode asymmetricMode) {
        try {
            return CryptoAsymmetricCustomUtil.restorePublicKey(asymmetricMode.getAlgorithm(), publicKeyStr);
        } catch (Exception e) {
            logger.error("获取: {} 公钥失败", asymmetricMode.getAlgorithm(), e);
            throw new SecurityException("获取" + asymmetricMode.getAlgorithm() + "公钥失败");
        }
    }

    /**
     * 私钥字符串还原
     *
     * @param privateKeyStr 私钥
     * @return 私钥的key
     */
    public static PrivateKey restorePrivateKey(String privateKeyStr, RequestAsymmetricMode asymmetricMode) {
        try {
            return CryptoAsymmetricCustomUtil.restorePrivateKey(asymmetricMode.getAlgorithm(), privateKeyStr);
        } catch (Exception e) {
            logger.error("获取: {} 私钥失败", asymmetricMode.getAlgorithm(), e);
            throw new SecurityException("获取" + asymmetricMode.getAlgorithm() + "私钥失败");
        }
    }

}    