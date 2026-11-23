package com.sgchen.security.core.util.algorithm;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * SM2 加密工具类，支持密钥生成、加密、解密等功能
 */
public class SM2Utils {
    static {
        // 注册 Bouncy Castle 安全提供程序
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // SM2 曲线参数
    private static final String SM2_CURVE_NAME = "sm2p256v1";

    /**
     * 生成 SM2 密钥对
     *
     * @return 密钥对
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(SM2_CURVE_NAME);
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 从 Base64 编码的字符串生成 SM2 公钥
     *
     * @param publicKeyBase64 Base64 编码的公钥字符串
     * @return 公钥
     * @throws Exception
     */
    public static PublicKey generatePublicKey(String publicKeyBase64) throws Exception {
        byte[] publicKeyBytes = Base64.decode(publicKeyBase64);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * 从 Base64 编码的字符串生成 SM2 私钥
     *
     * @param privateKeyBase64 Base64 编码的私钥字符串
     * @return 私钥
     * @throws Exception
     */
    public static PrivateKey generatePrivateKey(String privateKeyBase64) throws Exception {
        byte[] privateKeyBytes = Base64.decode(privateKeyBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 使用 SM2 公钥加密数据
     *
     * @param publicKey  公钥
     * @param plaintext  明文数据
     * @return 加密后的数据
     * @throws InvalidCipherTextException
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] plaintext) throws InvalidCipherTextException {
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
        ECParameterSpec ecParameterSpec = bcecPublicKey.getParameters();
        ECCurve curve = ecParameterSpec.getCurve();
        ECPoint point = bcecPublicKey.getQ();
        ECDomainParameters domainParameters = new ECDomainParameters(curve, ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(point, domainParameters);

        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        return sm2Engine.processBlock(plaintext, 0, plaintext.length);
    }

    /**
     * 使用 SM2 私钥解密数据
     *
     * @param privateKey 私钥
     * @param ciphertext 密文数据
     * @return 解密后的明文
     * @throws InvalidCipherTextException
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) throws InvalidCipherTextException {
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
        ECParameterSpec ecParameterSpec = bcecPrivateKey.getParameters();
        ECCurve curve = ecParameterSpec.getCurve();
        ECDomainParameters domainParameters = new ECDomainParameters(curve, ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(), domainParameters);

        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, privateKeyParameters);
        return sm2Engine.processBlock(ciphertext, 0, ciphertext.length);
    }

    /**
     * 将公钥转换为 Base64 编码字符串
     *
     * @param publicKey 公钥
     * @return Base64 编码字符串
     */
    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.toBase64String(publicKey.getEncoded());
    }

    /**
     * 将私钥转换为 Base64 编码字符串
     *
     * @param privateKey 私钥
     * @return Base64 编码字符串
     */
    public static String privateKeyToBase64(PrivateKey privateKey) {
        return Base64.toBase64String(privateKey.getEncoded());
    }

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        String publicKeyBase64 = publicKeyToBase64(keyPair.getPublic());
        String privateKeyBase64 = privateKeyToBase64(keyPair.getPrivate());
        System.out.println("公钥: " + publicKeyBase64);
        System.out.println("私钥: " + privateKeyBase64);

        // 加密
        String plaintext = "Hello, SM2 encryption!";
        byte[] encrypted = encrypt(keyPair.getPublic(), plaintext.getBytes());
        String encryptedBase64 = Base64.toBase64String(encrypted);
        System.out.println("加密后: " + encryptedBase64);

        // 解密
        byte[] decrypted = decrypt(keyPair.getPrivate(), encrypted);
        String decryptedText = new String(decrypted);
        System.out.println("解密后: " + decryptedText);
    }
}