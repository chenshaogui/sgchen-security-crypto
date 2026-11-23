package com.sgchen.security.core.util.algorithm;


import com.sgchen.security.core.enums.SecretAlgorithm;
import com.sgchen.security.core.exception.DataSecurityException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.*;


@Slf4j
public class CryptoSM4Util {

    private CryptoSM4Util() {
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String ALGORITHM = "SM4";


    public static String encrypt(String str, String hexKey, SecretAlgorithm algorithm) {
        try {
            byte[] key = Hex.decode(hexKey);
            Cipher cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGORITHM));
            return Base64.encodeBase64String(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            if(Boolean.TRUE.equals(algorithm.getIsSkipError())){
                log.warn("【SM4】数据【{}】加密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【SM4】数据【{}】加密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String decrypt(String str, String hexKey, SecretAlgorithm algorithm) {
        try {
            byte[] key = Hex.decode(hexKey);
            byte[] bytes = Base64.decodeBase64(str.getBytes());
            Cipher cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGORITHM));
            return new String(cipher.doFinal(bytes), StandardCharsets.UTF_8);
        } catch (Exception e) {
            if(Boolean.TRUE.equals(algorithm.getIsSkipError())){
                log.warn("【SM4】数据【{}】解密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【SM4】数据【{}】解密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String decryptIgnoreError(String str, String hexKey, SecretAlgorithm algorithm) {
        try {
            byte[] key = Hex.decode(hexKey);
            byte[] bytes = Base64.decodeBase64(str.getBytes());
            Cipher cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGORITHM));
            return new String(cipher.doFinal(bytes), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return str;
        }
    }

    // CBC模式加密(需16字节IV)
    public static String encrypt(String str, String hexKey, String hexIv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(hexIv)) {
            return encrypt(str, hexKey, algorithm);
        }
        try {
            byte[] key = Hex.decode(hexKey);
            byte[] iv = handleIVBytes(hexIv);
            Cipher cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, ALGORITHM),
                    new IvParameterSpec(iv));
            return Base64.encodeBase64String(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            if(Boolean.TRUE.equals(algorithm.getIsSkipError())){
                log.warn("【SM4+IV】数据【{}】加密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【SM4+IV】数据【{}】加密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String decrypt(String str, String hexKey, String hexIv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(hexIv)) {
            return decrypt(str, hexKey, algorithm);
        }
        try {
            byte[] key = Hex.decode(hexKey);
            byte[] iv = handleIVBytes(hexIv);
            byte[] bytes = Base64.decodeBase64(str.getBytes());
            Cipher cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, ALGORITHM),
                    new IvParameterSpec(iv));
            return new String(cipher.doFinal(bytes), StandardCharsets.UTF_8);
        } catch (Exception e) {
            if(Boolean.TRUE.equals(algorithm.getIsSkipError())){
                log.warn("【SM4+IV】数据【{}】解密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【SM4+IV】数据【{}】解密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String decryptIgnoreError(String str, String hexKey, String hexIv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(hexIv)) {
            return decryptIgnoreError(str, hexKey, algorithm);
        }
        try {
            byte[] key = Hex.decode(hexKey);
            byte[] iv = handleIVBytes(hexIv);
            byte[] bytes = Base64.decodeBase64(str.getBytes());
            Cipher cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, ALGORITHM),
                    new IvParameterSpec(iv));
            return new String(cipher.doFinal(bytes), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return str;
        }
    }

    private static byte[] handleIVBytes(String iv) {
        final int IV_SIZE_BYTES = 16; // 固定 16 字节 (128 位)

        // 1. 尝试作为 Base64 解码
        try {
            byte[] decoded = Base64.decodeBase64(iv);
            if (decoded.length == IV_SIZE_BYTES) {
                return decoded;
            }
        } catch (Exception ignored) {
            // 非 Base64 格式，继续尝试 Hex
        }

        // 2. 尝试作为 Hex 解码
        try {
            byte[] decoded = Hex.decode(iv);
            if (decoded.length == IV_SIZE_BYTES) {
                return decoded;
            }
        } catch (Exception ignored) {
            // 非 Hex 格式，继续下一步
        }

        // 3. 检查原始字符串字节长度
        byte[] rawBytes = iv.getBytes(StandardCharsets.UTF_8);
        if (rawBytes.length == IV_SIZE_BYTES) {
            return rawBytes;
        }

        // 4. 所有情况均不匹配，抛出异常
        throw new IllegalArgumentException(
                "IV 长度必须为 16 字节，但实际为: " + rawBytes.length);
    }

}


