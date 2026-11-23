package com.sgchen.security.core.util.algorithm;

import com.sgchen.security.core.enums.SecretAlgorithm;
import com.sgchen.security.core.exception.DataSecurityException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * @version V1.0
 * @desc AES 加密工具类
 */
@Slf4j
public class CryptoAESUtil {

    private CryptoAESUtil() {
    }

    private static boolean initialized = false;
    private static final String KEY_ALGORITHM = "AES";
    private static final byte[] iv = {0x30, 0x31, 0x33, 0x32, 0x30, 0x33, 0x31, 0x34, 0x30, 0x35, 0x31, 0x36, 0x30, 0x37, 0x30, 0x38};

    public static void initialize() {
        if (initialized) {
            return;
        }
        Security.addProvider(new BouncyCastleProvider());
        initialized = true;
    }

    /**
     * 生成加密秘钥
     *
     * @return key
     */
    private static Key getSecretKey(byte[] keyBytes) {
        //返回生成指定算法密钥生成器的 KeyGenerator 对象
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance(KEY_ALGORITHM);
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(keyBytes);
            //AES 要求密钥长度为 128
            kg.init(128, random);
            //生成一个密钥
            SecretKey secretKey = kg.generateKey();
            return new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM);// 转换为AES专用密钥
        } catch (NoSuchAlgorithmException ex) {
            throw new DataSecurityException("生成加密秘钥异常:" + ex.getMessage());
        }
    }

    public static Key getKey(byte[] keyBytes) {
        // 如果密钥不足16位，那么就补足.  这个if 中的内容很重要
        int base = 16;
        if (keyBytes.length % base != 0) {
            int groups = keyBytes.length / base + 1;
            byte[] temp = new byte[groups * base];
            Arrays.fill(temp, (byte) 0);
            System.arraycopy(keyBytes, 0, temp, 0, keyBytes.length);
            keyBytes = temp;
        }
        // 转化成JAVA的密钥格式
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    /**
     * 加密方法
     *
     * @param content  要加密的字符串
     * @param keyBytes 加密密钥
     * @return byte
     */
    public static byte[] encrypt(byte[] content, byte[] keyBytes, SecretAlgorithm algorithm) {
        return encrypt(content, keyBytes, iv, algorithm);
    }

    public static byte[] encrypt(byte[] content, byte[] keyBytes, byte[] ivBytes, SecretAlgorithm algorithm) {
        byte[] encryptedText = null;
        try {
            Key key;
            Cipher cipher;
            initialize();
            if (algorithm.equals(SecretAlgorithm.AES_ECB_PKCS5)) {
                key = getSecretKey(keyBytes);
                cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm());// 创建密码器

            } else {
                key = getKey(keyBytes);
                cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm(), "BC");
            }
            if (algorithm.equals(SecretAlgorithm.AES_ECB_PKCS5) || algorithm.equals(SecretAlgorithm.AES_ECB_PKCS7)) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            }
            encryptedText = cipher.doFinal(content);
        } catch (Exception e) {
            throw new DataSecurityException(e.getMessage());
        }
        return encryptedText;
    }

    /**
     * 解密方法
     *
     * @param encryptedData 要解密的字符串
     * @param keyBytes      解密密钥
     * @return byte
     */
    public static byte[] decrypt(byte[] encryptedData, byte[] keyBytes, SecretAlgorithm algorithm) {
        return decrypt(encryptedData, keyBytes, iv, algorithm);
    }

    public static byte[] decrypt(byte[] encryptedData, byte[] keyBytes, byte[] ivBytes, SecretAlgorithm algorithm) {
        byte[] encryptedText = null;
        try {
            Key key;
            Cipher cipher;
            initialize();
            if (algorithm.equals(SecretAlgorithm.AES_ECB_PKCS5)) {
                key = getSecretKey(keyBytes);
                cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm());// 创建密码器

            } else {
                key = getKey(keyBytes);
                cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm(), "BC");
            }
            if (algorithm.equals(SecretAlgorithm.AES_ECB_PKCS5) || algorithm.equals(SecretAlgorithm.AES_ECB_PKCS7)) {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            }
            encryptedText = cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new DataSecurityException(e.getMessage());
        }
        return encryptedText;
    }

    /**
     * @param str 要被加密的字符串
     * @param key 加/解密要用的长度为32的字节数组（256位）密钥
     * @return byte[]  加密后的字节数组
     */
    public static String encrypt(String str, String key, SecretAlgorithm algorithm) {
        try {
            byte[] bytes = encrypt(str.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8), algorithm);
            return Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            if (Boolean.TRUE.equals(algorithm.getIsSkipError())) {
                log.warn("【AES】数据【{}】加密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【AES】数据【{}】加密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String encrypt(String str, String key, String iv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(iv)) {
            return encrypt(str, key, algorithm);
        }
        try {
            byte[] bytes = encrypt(str.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8), handleIVBytes(iv) , algorithm);
            return Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            if (Boolean.TRUE.equals(algorithm.getIsSkipError())) {
                log.warn("【AES+IV】数据【{}】加密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【AES+IV】数据【{}】加密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String encryptByPKCS5(String str, String key) {
        return encrypt(str, key, SecretAlgorithm.AES_ECB_PKCS5);
    }

    public static String encryptByPKCS7(String str, String key) {
        return encrypt(str, key, SecretAlgorithm.AES_ECB_PKCS7);
    }

    public static String encryptByCBCPKCS7(String str, String key) {
        return encrypt(str, key, SecretAlgorithm.AES_CBC_PKCS7);
    }

    /**
     * @param str 要被解密的字节数组
     * @param key 加/解密要用的长度为32的字节数组（256位）密钥
     * @return String  解密后的字符串
     */
    public static String decrypt(String str, String key, SecretAlgorithm algorithm) {
        try {
            byte[] bytes = Base64.decodeBase64(str.getBytes());
            bytes = decrypt(bytes, key.getBytes(StandardCharsets.UTF_8), algorithm);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            if (Boolean.TRUE.equals(algorithm.getIsSkipError())) {
                log.warn("【AES】数据【{}】解密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【AES】数据【{}】解密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String decryptIgnoreError(String str, String key, SecretAlgorithm algorithm) {
        try {
            byte[] bytes = Base64.decodeBase64(str.getBytes());
            bytes = decrypt(bytes, key.getBytes(StandardCharsets.UTF_8), algorithm);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return str;
        }
    }

    public static String decrypt(String str, String key, String iv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(iv)) {
            return decrypt(str, key, algorithm);
        }
        try {
            byte[] bytes = Base64.decodeBase64(str.getBytes());
            bytes = decrypt(bytes, key.getBytes(StandardCharsets.UTF_8), handleIVBytes(iv), algorithm);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            if (Boolean.TRUE.equals(algorithm.getIsSkipError())) {
                log.warn("【AES+IV】数据【{}】解密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【AES+IV】数据【{}】解密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String decryptIgnoreError(String str, String key, String iv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(iv)) {
            return decryptIgnoreError(str, key, algorithm);
        }
        try {
            byte[] bytes = Base64.decodeBase64(str.getBytes());
            bytes = decrypt(bytes, key.getBytes(StandardCharsets.UTF_8), handleIVBytes(iv), algorithm);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return str;
        }
    }

    public static String decryptByPKCS5(String str, String key) {
        return decrypt(str, key, SecretAlgorithm.AES_ECB_PKCS5);
    }

    public static String decryptByPKCS7(String str, String key) {
        return decrypt(str, key, SecretAlgorithm.AES_ECB_PKCS7);
    }

    public static String decryptByCBCPKCS7(String str, String key) {
        return decrypt(str, key, SecretAlgorithm.AES_CBC_PKCS7);
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

    public static void main(String[] args) {
        // 1. 生成密钥
        String key = "0123456789abcdef0123456789abcdef";
        System.out.println("AES Key: " + key);

        // 2. ECB模式加解密
        String plainText = "Hello";
        String cipherText = encrypt(plainText, key, SecretAlgorithm.AES_ECB_PKCS7);
        System.out.println("ECB Encrypted: " + cipherText);
        System.out.println("ECB Decrypted: " + decrypt(cipherText, key, SecretAlgorithm.AES_ECB_PKCS7));

        // 3. CBC模式加解密（需生成16字节IV）
        String iv = "0102030405060708";
        System.out.println("CBC IV: " + iv);
        String cbcCipher = encrypt(plainText, key, iv, SecretAlgorithm.AES_CBC_PKCS7);
        System.out.println("CBC Encrypted: " + cbcCipher);
        System.out.println("CBC Decrypted: " + decrypt(cbcCipher, key, iv, SecretAlgorithm.AES_CBC_PKCS7));

    }

}
