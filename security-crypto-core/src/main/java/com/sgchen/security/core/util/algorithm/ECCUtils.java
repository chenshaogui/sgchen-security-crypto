package com.sgchen.security.core.util.algorithm;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.*;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * ECC 加密工具类，支持密钥生成、加密、解密等功能
 */
public class ECCUtils {
    static {
        // 注册 Bouncy Castle 安全提供程序
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // 默认曲线名称
    public static final String DEFAULT_CURVE = "secp256r1";
    // 密钥协议算法
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";
    // 加密算法
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    // 密钥长度
    private static final int AES_KEY_SIZE = 256;
    // GCM 认证标签长度
    private static final int GCM_TAG_LENGTH = 128;
    // GCM 初始向量长度
    private static final int GCM_IV_LENGTH = 12;

    /**
     * 生成 ECC 密钥对
     * @return 密钥对
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return generateKeyPair(DEFAULT_CURVE);
    }

    /**
     * 生成 ECC 密钥对
     * @param curveName 曲线名称，如 "secp256r1"
     * @return 密钥对
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateKeyPair(String curveName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 从 Base64 编码的字符串生成 ECC 公钥
     * @param publicKeyBase64 Base64 编码的公钥字符串
     * @param curveName 曲线名称
     * @return 公钥
     * @throws Exception
     */
    public static PublicKey generatePublicKey(String publicKeyBase64, String curveName) throws Exception {
        byte[] publicKeyBytes = Base64.decode(publicKeyBase64);
        return generatePublicKey(publicKeyBytes, curveName);
    }

    /**
     * 从字节数组生成 ECC 公钥
     * @param publicKeyBytes 公钥字节数组
     * @param curveName 曲线名称
     * @return 公钥
     * @throws Exception
     */
    public static PublicKey generatePublicKey(byte[] publicKeyBytes, String curveName) throws Exception {
       /* ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec(curveName);
        if (curveSpec == null) {
            throw new IllegalArgumentException("Unknown curve: " + curveName);
        }
        ECPoint point = curveSpec.getCurve().decodePoint(publicKeyBytes);
        ECParameterSpec spec = new ECParameterSpec(
                curveSpec.getCurve(),
                curveSpec.getG(),
                curveSpec.getN(),
                curveSpec.getH()
        );
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, spec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);*/

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * 从 Base64 编码的字符串生成 ECC 私钥
     * @param privateKeyBase64 Base64 编码的私钥字符串
     * @param curveName 曲线名称
     * @return 私钥
     * @throws Exception
     */
    public static PrivateKey generatePrivateKey(String privateKeyBase64, String curveName) throws Exception {
        byte[] privateKeyBytes = Base64.decode(privateKeyBase64);
        return generatePrivateKey(privateKeyBytes, curveName);
    }

    /**
     * 从字节数组生成 ECC 私钥
     * @param privateKeyBytes 私钥字节数组
     * @param curveName 曲线名称
     * @return 私钥
     * @throws Exception
     */
    public static PrivateKey generatePrivateKey(byte[] privateKeyBytes, String curveName) throws Exception {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
            if (spec == null) {
                throw new IllegalArgumentException("Unknown curve: " + curveName);
            }
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKeyBytes);
            org.bouncycastle.asn1.sec.ECPrivateKey ecPrivateKey =
                    org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(privateKeyInfo.parsePrivateKey());
            java.math.BigInteger s = ecPrivateKey.getKey();
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, spec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePrivate(keySpec);
        }
    }

    /**
     * 使用 ECC 公钥加密数据
     * @param publicKey 公钥
     * @param plaintext 明文数据
     * @return 加密后的数据（格式：ephemeral 公钥长度 + ephemeral 公钥 + IV + 密文 + 认证标签）
     * @throws Exception
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
        // 生成临时 ECC 密钥对用于密钥交换
        KeyPair ephemeralKeyPair = generateKeyPair();
        PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
        PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();

        // 执行 ECDH 密钥交换，生成共享密钥
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        keyAgreement.init(ephemeralPrivateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // 从共享密钥派生 AES 密钥
        SecretKey secretKey = deriveAESKey(sharedSecret);

        // 生成随机 IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        // 初始化 AES-GCM 加密器
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // 加密数据
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] ephemeralPublicKeyBytes = ephemeralPublicKey.getEncoded();
        int publicKeyLength = ephemeralPublicKeyBytes.length;

        // 合并公钥长度、ephemeral 公钥、IV 和密文
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(intToBytes(publicKeyLength));
        outputStream.write(ephemeralPublicKeyBytes);
        outputStream.write(iv);
        outputStream.write(ciphertext);

        return outputStream.toByteArray();
    }

    /**
     * 使用 ECC 私钥解密数据
     * @param privateKey 私钥
     * @param ciphertext 密文数据（格式：ephemeral 公钥长度 + ephemeral 公钥 + IV + 密文 + 认证标签）
     * @return 解密后的明文
     * @throws Exception
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) throws Exception {
        // 解析公钥长度
        int publicKeyLength = bytesToInt(Arrays.copyOfRange(ciphertext, 0, 4));

        // 解析 ephemeral 公钥
        byte[] ephemeralPublicKeyBytes = Arrays.copyOfRange(ciphertext, 4, 4 + publicKeyLength);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(ephemeralPublicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey ephemeralPublicKey = keyFactory.generatePublic(publicKeySpec);

        // 解析 IV
        byte[] iv = Arrays.copyOfRange(ciphertext, 4 + publicKeyLength, 4 + publicKeyLength + GCM_IV_LENGTH);

        // 解析加密数据
        byte[] encryptedData = Arrays.copyOfRange(ciphertext, 4 + publicKeyLength + GCM_IV_LENGTH, ciphertext.length);

        // 执行 ECDH 密钥交换，生成共享密钥
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(ephemeralPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // 从共享密钥派生 AES 密钥
        SecretKey secretKey = deriveAESKey(sharedSecret);

        // 初始化 AES-GCM 解密器
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        // 解密数据
        return cipher.doFinal(encryptedData);
    }

    /**
     * 从共享密钥派生 AES 密钥
     * @param sharedSecret 共享密钥
     * @return AES 密钥
     */
    private static SecretKey deriveAESKey(byte[] sharedSecret) {
        byte[] keyBytes = Arrays.copyOf(sharedSecret, AES_KEY_SIZE / 8);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * 将 int 转换为 4 字节数组
     * @param value 整数值
     * @return 字节数组
     */
    private static byte[] intToBytes(int value) {
        return new byte[]{
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }

    /**
     * 将 4 字节数组转换为 int
     * @param bytes 字节数组
     * @return 整数值
     */
    private static int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    /**
     * 将公钥转换为 Base64 编码字符串
     * @param publicKey 公钥
     * @return Base64 编码字符串
     */
    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.toBase64String(publicKey.getEncoded());
    }

    /**
     * 将私钥转换为 Base64 编码字符串
     * @param privateKey 私钥
     * @return Base64 编码字符串
     */
    public static String privateKeyToBase64(PrivateKey privateKey) {
        return Base64.toBase64String(privateKey.getEncoded());
    }

    /**
     * 将字节数组转换为十六进制字符串
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = generateKeyPair("secp256r1");
        String publicKeyBase64 = publicKeyToBase64(keyPair.getPublic());
        String privateKeyBase64 = privateKeyToBase64(keyPair.getPrivate());
        System.out.println("公钥: " + publicKeyBase64);
        System.out.println("私钥: " + privateKeyBase64);

        // 加密
        String plaintext = "Hello, ECC encryption!";
        byte[] encrypted = encrypt(keyPair.getPublic(), plaintext.getBytes());
        String encryptedBase64 = Base64.toBase64String(encrypted);
        System.out.println("加密后: " + encryptedBase64);

        // 解密
        byte[] decrypted = decrypt(keyPair.getPrivate(), encrypted);
        String decryptedText = new String(decrypted);
        System.out.println("解密后: " + decryptedText);
    }
}