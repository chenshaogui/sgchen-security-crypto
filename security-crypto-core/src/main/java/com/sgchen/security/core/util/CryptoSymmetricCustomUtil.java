package com.sgchen.security.core.util;

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
import java.security.*;

/**
 * @version V1.0
 * @description 自定义 对称 加密工具类
 */
@Slf4j
public class CryptoSymmetricCustomUtil {

    private CryptoSymmetricCustomUtil() {
    }

    private static boolean initialized = false;

    static {
        // 注册 Bouncy Castle 安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            initialize();
        }
    }

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
    private static Key getSecretKey(byte[] keyBytes, SecretAlgorithm secretAlgorithm) {
        String[] encryptAlgorithmArr = secretAlgorithm.getEncryptAlgorithm().split("/");
        //返回生成指定算法密钥生成器的 KeyGenerator 对象
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance(encryptAlgorithmArr[0]);
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(keyBytes);
            kg.init(secretAlgorithm.getKeySize(), random);
            //生成一个密钥
            SecretKey secretKey = kg.generateKey();
            return new SecretKeySpec(secretKey.getEncoded(), encryptAlgorithmArr[0]);
        } catch (NoSuchAlgorithmException ex) {
            throw new DataSecurityException("生成加密秘钥异常:" + ex.getMessage());
        }
    }

    public static Key getKey(byte[] keyBytes, SecretAlgorithm secretAlgorithm) {
        String[] encryptAlgorithmArr = secretAlgorithm.getEncryptAlgorithm().split("/");
        // 转化成JAVA的密钥格式
        return new SecretKeySpec(keyBytes, encryptAlgorithmArr[0]);
    }

    /**
     * 加密方法
     *
     * @param content  要加密的字符串
     * @param keyBytes 加密密钥
     * @return byte
     */
    public static byte[] encrypt(byte[] content, byte[] keyBytes, SecretAlgorithm algorithm) {
        return encrypt(content, keyBytes, null, algorithm);
    }

    public static byte[] encrypt(byte[] content, byte[] keyBytes, byte[] ivBytes, SecretAlgorithm algorithm) {
        byte[] encryptedText = null;
        try {
            Key key;
            Cipher cipher;
            initialize();
            key = getKey(keyBytes, algorithm);
            cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm(), "BC");
            if (ivBytes == null) {
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
        return decrypt(encryptedData, keyBytes, null, algorithm);
    }

    public static byte[] decrypt(byte[] encryptedData, byte[] keyBytes, byte[] ivBytes, SecretAlgorithm algorithm) {
        byte[] encryptedText = null;
        try {
            Key key;
            Cipher cipher;
            initialize();
            key = getKey(keyBytes, algorithm);
            cipher = Cipher.getInstance(algorithm.getEncryptAlgorithm(), "BC");
            if (ivBytes == null) {
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
                log.warn("【对称自定义加密】数据【{}】加密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【对称自定义加密】数据【{}】加密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
    }

    public static String encrypt(String str, String key, String iv, SecretAlgorithm algorithm) {
        if (StringUtils.isEmpty(iv)) {
            return encrypt(str, key, algorithm);
        }
        try {
            byte[] bytes = encrypt(str.getBytes(StandardCharsets.UTF_8), handleKeyBytes(key, algorithm), handleIVBytes(iv, algorithm), algorithm);
            return Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            if (Boolean.TRUE.equals(algorithm.getIsSkipError())) {
                log.warn("【对称自定义加密+IV】数据【{}】加密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【对称自定义加密+IV】数据【{}】加密失败：{}", str, e.getMessage(), e);
                throw new DataSecurityException(e.getMessage());
            }
        }
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
                log.warn("【对称自定义加密】数据【{}】解密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【对称自定义加密】数据【{}】解密失败：{}", str, e.getMessage(), e);
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
            bytes = decrypt(bytes, handleKeyBytes(key, algorithm), handleIVBytes(iv, algorithm), algorithm);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            if (Boolean.TRUE.equals(algorithm.getIsSkipError())) {
                log.warn("【对称自定义加密+IV】数据【{}】解密失败：{}，返回原数据", str, e.getMessage());
                return str;
            } else {
                log.error("【对称自定义加密+IV】数据【{}】解密失败：{}", str, e.getMessage(), e);
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
            bytes = decrypt(bytes, handleKeyBytes(key, algorithm), handleIVBytes(iv, algorithm), algorithm);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return str;
        }
    }

    private static byte[] handleIVBytes(String iv, SecretAlgorithm algorithm) {
        int ivSizeBytes = algorithm.getIvSize(); // IV 大小（字节）

        // 1. 先尝试作为 Base64 解码
        try {
            byte[] decoded = Base64.decodeBase64(iv);
            if (decoded.length == ivSizeBytes) {
                return decoded;
            }
        } catch (Exception ignored) {
            // 不是有效的 Base64，继续尝试 Hex
        }

        // 2. 再尝试作为 Hex 解码
        try {
            byte[] decoded = Hex.decode(iv);
            if (decoded.length == ivSizeBytes) {
                return decoded;
            }
        } catch (Exception ignored) {
            // 不是有效的 Hex，继续下一步
        }

        // 3. 检查原始字符串的字节长度是否符合要求
        byte[] rawBytes = iv.getBytes(StandardCharsets.UTF_8);
        if (rawBytes.length == ivSizeBytes) {
            return rawBytes;
        }

        // 4. 都不符合，抛出异常（IV 长度必须严格匹配）
        throw new IllegalArgumentException(
                "IV 长度不匹配！需要 " + ivSizeBytes + " 字节，但实际为: " + rawBytes.length);
    }

    private static byte[] handleKeyBytes(String key, SecretAlgorithm algorithm) throws NoSuchAlgorithmException {
        int keySizeBytes = getDefaultKeySize(algorithm); // 转换为字节
        // 1. 先尝试作为 Base64 解码
        try {
            byte[] decoded = Base64.decodeBase64(key);
            if (decoded.length == keySizeBytes) {
                return decoded;
            }
        } catch (Exception ignored) {
            // 不是有效的 Base64，继续尝试 Hex
        }

        // 2. 再尝试作为 Hex 解码
        try {
            byte[] decoded = Hex.decode(key);
            if (decoded.length == keySizeBytes) {
                return decoded;
            }
        } catch (Exception ignored) {
            // 不是有效的 Hex，继续下一步
        }

        // 3. 检查原始字符串的字节长度是否符合要求
        byte[] rawBytes = key.getBytes(StandardCharsets.UTF_8);
        if (rawBytes.length == keySizeBytes) {
            return rawBytes;
        }

        // 4. 都不符合，抛出异常或截断/填充（根据需求选择）
        throw new IllegalArgumentException(
                "密钥长度不匹配！需要 " + keySizeBytes + " 字节，但实际为: " + rawBytes.length);
    }

    // 生成16字节HEX格式密钥
    public static String generateKeyHex(SecretAlgorithm algorithm) throws NoSuchAlgorithmException {
        String[] encryptAlgorithmArr = algorithm.getEncryptAlgorithm().split("/");
        KeyGenerator kg = KeyGenerator.getInstance(encryptAlgorithmArr[0]);
        kg.init(algorithm.getKeySize(), new SecureRandom());
        return Hex.toHexString(kg.generateKey().getEncoded());
    }

    /**
     * 获取算法的默认密钥长度（若未指定）
     */
    public static int getDefaultKeySize(SecretAlgorithm algorithm) throws NoSuchAlgorithmException {
        String[] encryptAlgorithmArr = algorithm.getEncryptAlgorithm().split("/");
        KeyGenerator kg = KeyGenerator.getInstance(encryptAlgorithmArr[0]);
        kg.init(algorithm.getKeySize(), new SecureRandom());
        return kg.generateKey().getEncoded().length;
    }

    // 生成16字节HEX格式IV
    public static String generateIvHex(SecretAlgorithm algorithm) {
        byte[] iv = new byte[algorithm.getIvSize()];
        new SecureRandom().nextBytes(iv);
        return Hex.toHexString(iv);
    }

    public static String generateIVBase64(SecretAlgorithm algorithm) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[algorithm.getIvSize()];
        secureRandom.nextBytes(iv);
        return java.util.Base64.getEncoder().encodeToString(iv);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 自定义对称加解密支持，DES、3DES、Blowfish、RC4
        // 配置自定义算法
        SecretAlgorithm.configureCustomAlgorithm("DES/CBC/PKCS5Padding", false, 56, 8);

        SecretAlgorithm customAlgorithm = SecretAlgorithm.CUSTOM_ALGORITHM;
        // 1. 生成密钥
        String key = generateKeyHex(customAlgorithm);
//        key = "38badcf45d6d8c323";
        System.out.println("对称自定义加密 Key: " + key);

        String plainText = "Helloxxxxxx";
        // 3. CBC模式加解密
        String iv = generateIvHex(customAlgorithm);
//        iv = null;
        System.out.println("CBC IV: " + iv);
        String cbcCipher = encrypt(plainText, key, iv, customAlgorithm);
        System.out.println("CBC Encrypted: " + cbcCipher);
        System.out.println("CBC Decrypted: " + decrypt(cbcCipher, key, iv, customAlgorithm));
    }


}
