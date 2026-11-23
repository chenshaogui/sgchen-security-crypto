package com.sgchen.security.core.util;

import com.sgchen.security.core.enums.SecretAlgorithm;
import org.apache.commons.lang3.StringUtils;

/**
 * @version V1.0
 * @desc 加密工具类
 */
public class CryptoSymmetricUtil {

    private CryptoSymmetricUtil() {
    }

    // 生成HEX格式IV
    public static String generateIvHex(SecretAlgorithm algorithm) {
        return CryptoSymmetricCustomUtil.generateIvHex(algorithm);
    }

    // 生成 16 字节随机 IV 并转为 Base64 字符串
    public static String generateIVBase64(SecretAlgorithm algorithm) {
        return CryptoSymmetricCustomUtil.generateIVBase64(algorithm);
    }

    /**
     * @param str 要被加密的字符串
     * @param key 加/解密要用的长度为32的字节数组（256位）密钥
     * @return byte[]  加密后的字节数组
     */
    public static String encrypt(String str, String key, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(str)) {
            return str;
        }
        /*if (algorithm.getEncryptAlgorithm().startsWith("SM4")) {
            // 先解密数据，防止数据时加密
            str = CryptoSM4Util.decryptIgnoreError(str, key, algorithm);
            return CryptoSM4Util.encrypt(str, key, algorithm);
        }
        if (algorithm.getEncryptAlgorithm().startsWith("AES")) {
            str = CryptoAESUtil.decryptIgnoreError(str, key, algorithm);
            return CryptoAESUtil.encrypt(str, key, algorithm);
        }*/
        // 先解密数据，防止数据重复加密
        str = CryptoSymmetricCustomUtil.decryptIgnoreError(str, key, algorithm);
        return CryptoSymmetricCustomUtil.encrypt(str, key, algorithm);
    }

    public static String encrypt(String str, String key, String iv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(str)) {
            return str;
        }
        /*if (algorithm.getEncryptAlgorithm().startsWith("SM4")) {
            // 先解密数据，防止数据时加密
            str = CryptoSM4Util.decryptIgnoreError(str, key, iv, algorithm);
            return CryptoSM4Util.encrypt(str, key, iv, algorithm);
        }
        if (algorithm.getEncryptAlgorithm().startsWith("AES")) {
            str = CryptoAESUtil.decryptIgnoreError(str, key, iv, algorithm);
            return CryptoAESUtil.encrypt(str, key, iv, algorithm);
        }*/
        // 先解密数据，防止数据时加密
        str = CryptoSymmetricCustomUtil.decryptIgnoreError(str, key, iv, algorithm);
        return CryptoSymmetricCustomUtil.encrypt(str, key, iv, algorithm);
    }


    /**
     * @param str 要被解密的字节数组
     * @param key 加/解密要用的长度为32的字节数组（256位）密钥
     * @return String  解密后的字符串
     */
    public static String decrypt(String str, String key, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(str)) {
            return str;
        }
        /*if (algorithm.getEncryptAlgorithm().startsWith("SM4")) {
            return CryptoSM4Util.decrypt(str, key, algorithm);
        }
        if (algorithm.getEncryptAlgorithm().startsWith("AES")) {
            return CryptoAESUtil.decrypt(str, key, algorithm);
        }*/
        return CryptoSymmetricCustomUtil.decrypt(str, key, algorithm);
    }

    public static String decrypt(String str, String key, String iv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(str)) {
            return str;
        }
        /*if (algorithm.getEncryptAlgorithm().startsWith("SM4")) {
            return CryptoSM4Util.decrypt(str, key, iv, algorithm);
        }
        if (algorithm.getEncryptAlgorithm().startsWith("AES")) {
            return CryptoAESUtil.decrypt(str, key, iv, algorithm);
        }*/
        return CryptoSymmetricCustomUtil.decrypt(str, key, iv, algorithm);
    }

}
