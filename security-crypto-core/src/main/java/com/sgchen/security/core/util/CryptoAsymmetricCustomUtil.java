package com.sgchen.security.core.util;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.agreement.ECMQVBasicAgreement;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 通用非对称加密工具类，支持多种非对称密钥算法
 */
public class CryptoAsymmetricCustomUtil {
    static {
        // 注册 Bouncy Castle 安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    // 算法常量
    public static final String ALGORITHM_SM2 = "EC"; // SM2通用
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_DSA = "DSA";
    public static final String ALGORITHM_ELGAMAL = "ElGamal";
    public static final String ALGORITHM_ECDSA = "ECDSA";
    public static final String ALGORITHM_ECDH = "ECDH";
    public static final String ALGORITHM_MQV = "MQV";
    public static final String ALGORITHM_DIFFIE_HELLMAN = "DiffieHellman";

    /**
     * 从resources目录加载配置文件
     */
    public static Properties loadConfig(String resourcePath) throws IOException {
        Properties properties = new Properties();
        try (InputStream inputStream = CryptoAsymmetricCustomUtil.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new FileNotFoundException("Resource not found: " + resourcePath);
            }
            properties.load(inputStream);
        }
        return properties;
    }

    /**
     * 生成密钥对
     */
    public static KeyPair generateKeyPair(String algorithm, int keySize) throws Exception {
        switch (algorithm) {
            case ALGORITHM_SM2:
                return generateSM2KeyPair();
            case ALGORITHM_RSA:
                return generateRSAKeyPair(keySize);
            case ALGORITHM_DSA:
                return generateDSAKeyPair(keySize);
            case ALGORITHM_ELGAMAL:
                return generateElGamalKeyPair(keySize);
            case ALGORITHM_ECDSA:
            case ALGORITHM_ECDH:
                return generateECCKeyPair(keySize);
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    /**
     * 使用公钥加密
     */
    public static byte[] encrypt(String algorithm, PublicKey publicKey, byte[] plaintext) throws Exception {
        switch (algorithm) {
            case ALGORITHM_SM2:
                return sm2Encrypt(publicKey, plaintext);
            case ALGORITHM_RSA:
                return rsaEncrypt(publicKey, plaintext);
            case ALGORITHM_ELGAMAL:
                return elGamalEncrypt(publicKey, plaintext);
            case ALGORITHM_ECDSA:
            case ALGORITHM_ECDH:
                return eccEncrypt(publicKey, plaintext);
            default:
                throw new IllegalArgumentException("Encryption not supported for algorithm: " + algorithm);
        }
    }

    /**
     * 使用私钥解密
     */
    public static byte[] decrypt(String algorithm, PrivateKey privateKey, byte[] ciphertext) throws Exception {
        switch (algorithm) {
            case ALGORITHM_SM2:
                return sm2Decrypt(privateKey, ciphertext);
            case ALGORITHM_RSA:
                return rsaDecrypt(privateKey, ciphertext);
            case ALGORITHM_ELGAMAL:
                return elGamalDecrypt(privateKey, ciphertext);
            case ALGORITHM_ECDSA:
            case ALGORITHM_ECDH:
                return eccDecrypt(privateKey, ciphertext);
            default:
                throw new IllegalArgumentException("Decryption not supported for algorithm: " + algorithm);
        }
    }

    /**
     * 使用私钥签名
     */
    public static String sign(String algorithm, PrivateKey privateKey, byte[] data) throws Exception {
        switch (algorithm) {
            case ALGORITHM_SM2:
                return sm2Sign(privateKey, data);
            case ALGORITHM_RSA:
                return rsaSign(privateKey, data);
            case ALGORITHM_DSA:
                return dsaSign(privateKey, data);
            case ALGORITHM_ECDSA:
                return ecdsaSign(privateKey, data);
            default:
                throw new IllegalArgumentException("Signing not supported for algorithm: " + algorithm);
        }
    }

    /**
     * 使用公钥验证签名
     */
    public static boolean verify(String algorithm, PublicKey publicKey, byte[] data, String signatureBase64) throws Exception {
        switch (algorithm) {
            case ALGORITHM_SM2:
                return sm2Verify(publicKey, data, signatureBase64);
            case ALGORITHM_RSA:
                return rsaVerify(publicKey, data, signatureBase64);
            case ALGORITHM_DSA:
                return dsaVerify(publicKey, data, signatureBase64);
            case ALGORITHM_ECDSA:
                return ecdsaVerify(publicKey, data, signatureBase64);
            default:
                throw new IllegalArgumentException("Signature verification not supported for algorithm: " + algorithm);
        }
    }

    /**
     * 密钥交换（生成共享密钥）
     */
    public static byte[] generateSharedSecret(String algorithm, PrivateKey privateKey, PublicKey otherPublicKey) throws Exception {
        switch (algorithm) {
            case ALGORITHM_ECDH:
                return ecdhGenerateSharedSecret(privateKey, otherPublicKey);
            case ALGORITHM_DIFFIE_HELLMAN:
                return dhGenerateSharedSecret(privateKey, otherPublicKey);
            case ALGORITHM_MQV:
                return mqvGenerateSharedSecret(privateKey, otherPublicKey);
            default:
                throw new IllegalArgumentException("Key exchange not supported for algorithm: " + algorithm);
        }
    }

    // ==================== 私有实现方法 ====================

    // SM2 密钥对生成
    private static KeyPair generateSM2KeyPair() throws Exception {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    // RSA 密钥对生成
    private static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(keySize, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    // DSA 密钥对生成
    private static KeyPair generateDSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGenerator.initialize(keySize, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    // ElGamal 密钥对生成（更新版本）
    private static KeyPair generateElGamalKeyPair(int keySize) throws Exception {
        // 使用预生成的 ElGamal 参数
        ElGamalParameters params = getCachedElGamalParameters(keySize);

        // 生成密钥对
        ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
        keyPairGenerator.init(new ElGamalKeyGenerationParameters(new SecureRandom(), params));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 转换为 JCE 兼容格式
        ElGamalPublicKeyParameters pubParams = (ElGamalPublicKeyParameters) keyPair.getPublic();
        ElGamalPrivateKeyParameters privParams = (ElGamalPrivateKeyParameters) keyPair.getPrivate();

        // 创建自定义的 ElGamal 密钥类（使用 DHPublicKey/DHPrivateKey 接口）
        PublicKey publicKey = new CustomElGamalPublicKey(pubParams);
        PrivateKey privateKey = new CustomElGamalPrivateKey(privParams);

        return new KeyPair(publicKey, privateKey);
    }

    // 自定义 ElGamal 公钥实现（使用 DHPublicKey 接口）
    private static class CustomElGamalPublicKey implements DHPublicKey {
        private final ElGamalPublicKeyParameters params;
        private final byte[] encoded;

        public CustomElGamalPublicKey(ElGamalPublicKeyParameters params) {
            this.params = params;
            try {
                // 编码公钥
                this.encoded = encodePublicKey(params);
            } catch (IOException e) {
                throw new RuntimeException("Error encoding public key", e);
            }
        }

        @Override
        public BigInteger getY() {
            return params.getY();
        }

        @Override
        public DHParameterSpec getParams() {
            ElGamalParameters elParams = params.getParameters();
            return new DHParameterSpec(elParams.getP(), elParams.getG());
        }

        @Override
        public String getAlgorithm() {
            return "ElGamal";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return encoded.clone();
        }

        private byte[] encodePublicKey(ElGamalPublicKeyParameters params) throws IOException {
            DHParameter dhParams = new DHParameter(
                    params.getParameters().getP(),
                    params.getParameters().getG(),
                    0
            );

            AlgorithmIdentifier algId = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.dhKeyAgreement,
                    dhParams
            );

            // 使用 ASN1Integer 替代 DERInteger
            org.bouncycastle.asn1.ASN1Integer asn1Y = new org.bouncycastle.asn1.ASN1Integer(params.getY());

            SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algId, asn1Y);
            return publicKeyInfo.getEncoded();
        }

    }


    // 自定义 ElGamal 私钥实现（使用 DHPrivateKey 接口）
    private static class CustomElGamalPrivateKey implements DHPrivateKey {
        private final ElGamalPrivateKeyParameters params;
        private final byte[] encoded;

        public CustomElGamalPrivateKey(ElGamalPrivateKeyParameters params) {
            this.params = params;
            try {
                // 编码私钥
                this.encoded = encodePrivateKey(params);
            } catch (IOException e) {
                throw new RuntimeException("Error encoding private key", e);
            }
        }

        @Override
        public BigInteger getX() {
            return params.getX();
        }

        @Override
        public DHParameterSpec getParams() {
            ElGamalParameters elParams = params.getParameters();
            return new DHParameterSpec(elParams.getP(), elParams.getG());
        }

        @Override
        public String getAlgorithm() {
            return "ElGamal";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return encoded.clone();
        }

        private byte[] encodePrivateKey(ElGamalPrivateKeyParameters params) throws IOException {
            DHParameter dhParams = new DHParameter(
                    params.getParameters().getP(),
                    params.getParameters().getG(),
                    0
            );

            AlgorithmIdentifier algId = new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.dhKeyAgreement,
                    dhParams
            );

            // 使用 ASN1Integer 替代 DERInteger
            org.bouncycastle.asn1.ASN1Integer asn1X = new org.bouncycastle.asn1.ASN1Integer(params.getX());

            PrivateKeyInfo privateKeyInfo =
                    new PrivateKeyInfo(algId, asn1X);

            return privateKeyInfo.getEncoded();
        }
    }


    // ECC 密钥对生成
    private static KeyPair generateECCKeyPair(int keySize) throws Exception {
        // 获取曲线名称
        String curveName = getCurveName(keySize);
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);

        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    // SM2 加密
    private static byte[] sm2Encrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
        X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParameters = new ECDomainParameters(
                ecParameters.getCurve(),
                ecParameters.getG(),
                ecParameters.getN(),
                ecParameters.getH()
        );

        org.bouncycastle.jce.interfaces.ECPublicKey ecPublicKey =
                (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(
                ecPublicKey.getQ(),
                domainParameters
        );

        SM2Engine engine = new SM2Engine();
        engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        return engine.processBlock(plaintext, 0, plaintext.length);
    }

    // SM2 解密
    private static byte[] sm2Decrypt(PrivateKey privateKey, byte[] ciphertext) throws Exception {
        X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParameters = new ECDomainParameters(
                ecParameters.getCurve(),
                ecParameters.getG(),
                ecParameters.getN(),
                ecParameters.getH()
        );

        org.bouncycastle.jce.interfaces.ECPrivateKey ecPrivateKey =
                (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(
                ecPrivateKey.getD(),
                domainParameters
        );

        SM2Engine engine = new SM2Engine();
        engine.init(false, privateKeyParameters);
        return engine.processBlock(ciphertext, 0, ciphertext.length);
    }

    // RSA 加密
    private static byte[] rsaEncrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    // RSA 解密
    private static byte[] rsaDecrypt(PrivateKey privateKey, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    // ElGamal 加密（更新版本）
    private static byte[] elGamalEncrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
        // 将公钥转换为 DHPublicKey
        DHPublicKey dhPublicKey = (DHPublicKey) publicKey;

        // 提取参数
        BigInteger p = dhPublicKey.getParams().getP();
        BigInteger g = dhPublicKey.getParams().getG();
        BigInteger y = dhPublicKey.getY();

        // 创建 BC 参数
        ElGamalParameters parameters = new ElGamalParameters(p, g);
        ElGamalPublicKeyParameters pubParams = new ElGamalPublicKeyParameters(y, parameters);

        // 创建加密器
        ElGamalEngine engine = new ElGamalEngine();
        engine.init(true, pubParams);

        // 执行加密
        return engine.processBlock(plaintext, 0, plaintext.length);
    }


    // ElGamal 解密（更新版本）
    private static byte[] elGamalDecrypt(PrivateKey privateKey, byte[] ciphertext) throws Exception {
        // 将私钥转换为 DHPrivateKey
        DHPrivateKey dhPrivateKey = (DHPrivateKey) privateKey;

        // 提取参数
        BigInteger p = dhPrivateKey.getParams().getP();
        BigInteger g = dhPrivateKey.getParams().getG();
        BigInteger x = dhPrivateKey.getX();

        // 创建 BC 参数
        ElGamalParameters parameters = new ElGamalParameters(p, g);
        ElGamalPrivateKeyParameters privParams = new ElGamalPrivateKeyParameters(x, parameters);

        // 创建解密器
        ElGamalEngine engine = new ElGamalEngine();
        engine.init(false, privParams);

        // 执行解密
        return engine.processBlock(ciphertext, 0, ciphertext.length);
    }

    // SM2 签名
    private static String sm2Sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signBytes = signature.sign();
        return Base64.toBase64String(signBytes);
    }

    // SM2 验证签名
    private static boolean sm2Verify(PublicKey publicKey, byte[] data, String signatureBase64) throws Exception {
        Signature signature = Signature.getInstance("SM3withSM2", "BC");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64.decode(signatureBase64));
    }

    // RSA 签名
    private static String rsaSign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signBytes = signature.sign();
        return Base64.toBase64String(signBytes);
    }

    // RSA 验证签名
    private static boolean rsaVerify(PublicKey publicKey, byte[] data, String signatureBase64) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64.decode(signatureBase64));
    }

    // DSA 签名
    private static String dsaSign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA", "BC");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signBytes = signature.sign();
        return Base64.toBase64String(signBytes);
    }

    // DSA 验证签名
    private static boolean dsaVerify(PublicKey publicKey, byte[] data, String signatureBase64) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA", "BC");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64.decode(signatureBase64));
    }

    // ECDSA 签名
    private static String ecdsaSign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signBytes = signature.sign();
        return Base64.toBase64String(signBytes);
    }

    // ECDSA 验证签名
    private static boolean ecdsaVerify(PublicKey publicKey, byte[] data, String signatureBase64) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64.decode(signatureBase64));
    }

    // ECDH 生成共享密钥
    private static byte[] ecdhGenerateSharedSecret(PrivateKey privateKey, PublicKey otherPublicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(otherPublicKey, true);
        return keyAgreement.generateSecret();
    }

    // Diffie-Hellman 生成共享密钥
    private static byte[] dhGenerateSharedSecret(PrivateKey privateKey, PublicKey otherPublicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(otherPublicKey, true);
        return keyAgreement.generateSecret();
    }

    // MQV 生成共享密钥
    private static byte[] mqvGenerateSharedSecret(PrivateKey privateKey, PublicKey otherPublicKey) throws Exception {
        // 转换为 BC 格式的密钥
        org.bouncycastle.jce.interfaces.ECPrivateKey ecPrivateKey =
                (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
        org.bouncycastle.jce.interfaces.ECPublicKey ecPublicKey =
                (org.bouncycastle.jce.interfaces.ECPublicKey) otherPublicKey;

        X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParameters = new ECDomainParameters(
                ecParameters.getCurve(),
                ecParameters.getG(),
                ecParameters.getN(),
                ecParameters.getH()
        );

        ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(
                ecPrivateKey.getD(),
                domainParameters
        );

        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(
                ecPublicKey.getQ(),
                domainParameters
        );

        // MQV 密钥交换
        ECMQVBasicAgreement agreement = new ECMQVBasicAgreement();
        ParametersWithRandom paramWithRandom = new ParametersWithRandom(privateKeyParams, new SecureRandom());
        agreement.init(paramWithRandom);
        return agreement.calculateAgreement(publicKeyParams).toByteArray();
    }

    // ECC 加密 (使用 JCE 标准 API)
    private static byte[] eccEncrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
        // 创建 Cipher 实例，使用 ECIES 算法
        Cipher cipher = Cipher.getInstance("ECIES", "BC");

        // 配置参数
        org.bouncycastle.jce.spec.IESParameterSpec iesParams =
                new org.bouncycastle.jce.spec.IESParameterSpec(
                        null,        // 可选的盐值
                        null,        // 可选的附加数据
                        256          // 密钥长度
                );

        // 初始化加密模式
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, iesParams);

        // 执行加密
        return cipher.doFinal(plaintext);
    }

    // ECC 解密 (使用 JCE 标准 API)
    private static byte[] eccDecrypt(PrivateKey privateKey, byte[] ciphertext) throws Exception {
        // 创建 Cipher 实例，使用 ECIES 算法
        Cipher cipher = Cipher.getInstance("ECIES", "BC");

        // 配置参数 (必须与加密时相同)
        org.bouncycastle.jce.spec.IESParameterSpec iesParams =
                new org.bouncycastle.jce.spec.IESParameterSpec(
                        null,        // 可选的盐值
                        null,        // 可选的附加数据
                        256          // 密钥长度
                );

        // 初始化解密模式
        cipher.init(Cipher.DECRYPT_MODE, privateKey, iesParams);

        // 执行解密
        return cipher.doFinal(ciphertext);
    }

    // 根据密钥长度获取 ECC 曲线名称
    private static String getCurveName(int keySize) {
        switch (keySize) {
            case 192:
                return "prime192v1";
            case 224:
                return "prime224v1";
            case 256:
                return "prime256v1";
            case 384:
                return "secp384r1";
            case 521:
                return "secp521r1";
            case 233:
                return "sect233r1";
            case 283:
                return "sect283r1";
            case 409:
                return "sect409r1";
            case 571:
                return "sect571r1";
            default:
                return "prime256v1";
        }
    }

    // 缓存不同密钥长度的 ElGamal 参数
    private static final Map<Integer, ElGamalParameters> ELGAMAL_PARAMS_CACHE = new ConcurrentHashMap<>();

    // 获取缓存的 ElGamal 参数，如果不存在则生成并缓存
    private static ElGamalParameters getCachedElGamalParameters(int keySize) {
        return ELGAMAL_PARAMS_CACHE.computeIfAbsent(keySize, k -> {
            try {
                // 生成 ElGamal 参数
                ElGamalParametersGenerator paramGen = new ElGamalParametersGenerator();
                paramGen.init(k, 20, new SecureRandom());
                return paramGen.generateParameters();
            } catch (Exception e) {
                throw new RuntimeException("生成 ElGamal 参数失败", e);
            }
        });
    }

    /**
     * 示例用法
     */
    public static void main(String[] args) {
        try {
            // 加载配置
            Properties config = loadConfig("crypto.properties");
            String algorithm = config.getProperty("algorithm", ALGORITHM_SM2);
            int keySize = Integer.parseInt(config.getProperty("keySize", "2048"));
            String plaintext = config.getProperty("plaintext", "Hello, 加密测试!");

            // 生成密钥对
            KeyPair keyPair = generateKeyPair(algorithm, keySize);
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 加密
            byte[] ciphertext = encrypt(algorithm, publicKey, plaintext.getBytes(StandardCharsets.UTF_8));
            System.out.println("加密后: " + Base64.toBase64String(ciphertext).length());

            restorePublicKey(algorithm, Base64.toBase64String(publicKey.getEncoded()));
            // 解密
            byte[] decrypted = decrypt(algorithm, privateKey, ciphertext);
            System.out.println("解密后: " + new String(decrypted, StandardCharsets.UTF_8));

            // 签名
            String signature = sign(algorithm, privateKey, plaintext.getBytes(StandardCharsets.UTF_8));
            System.out.println("签名: " + signature);

            // 验证签名
            boolean isValid = verify(algorithm, publicKey, plaintext.getBytes(StandardCharsets.UTF_8), signature);
            System.out.println("签名验证结果: " + isValid);

            // 密钥交换（如果支持）
            if (supportsKeyExchange(algorithm)) {
                // 生成第二个密钥对用于密钥交换
                KeyPair otherKeyPair = generateKeyPair(algorithm, keySize);
                byte[] sharedSecret = generateSharedSecret(
                        algorithm,
                        keyPair.getPrivate(),
                        otherKeyPair.getPublic()
                );
                System.out.println("共享密钥: " + Base64.toBase64String(sharedSecret));
            }

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // 判断算法是否支持密钥交换
    private static boolean supportsKeyExchange(String algorithm) {
        return algorithm.equals(ALGORITHM_ECDH) ||
                algorithm.equals(ALGORITHM_DIFFIE_HELLMAN) ||
                algorithm.equals(ALGORITHM_MQV);
    }

    /**
     * 将公钥字符串还原为 PublicKey 对象
     *
     * @param algorithm    算法名称
     * @param publicKeyStr 公钥字符串（Base64 编码）
     * @return PublicKey 对象
     * @throws Exception 异常
     */
    public static PublicKey restorePublicKey(String algorithm, String publicKeyStr) throws Exception {
        byte[] keyBytes = Base64.decode(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, "BC");
        switch (algorithm) {
            case ALGORITHM_RSA:
            case ALGORITHM_DSA:
            case ALGORITHM_ECDSA:
            case ALGORITHM_ECDH:
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                return keyFactory.generatePublic(keySpec);
            case ALGORITHM_ELGAMAL:
                SubjectPublicKeyInfo sPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyBytes);
                ElGamalPublicKeyParameters pubParams = (ElGamalPublicKeyParameters) PublicKeyFactory.createKey(sPublicKeyInfo);
                return new CustomElGamalPublicKey(pubParams);
            case ALGORITHM_SM2:
                SubjectPublicKeyInfo sPublicKeyInfo1 = SubjectPublicKeyInfo.getInstance(keyBytes);
                X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
                // 类型转换
                ECField field = new ECFieldFp(ecParameters.getCurve().getField().getCharacteristic());
                EllipticCurve ellipticCurve = new EllipticCurve(
                        field,
                        ecParameters.getCurve().getA().toBigInteger(),
                        ecParameters.getCurve().getB().toBigInteger()
                );

                // 转换基点 G
                ECPoint g = new ECPoint(
                        ecParameters.getG().getAffineXCoord().toBigInteger(),
                        ecParameters.getG().getAffineYCoord().toBigInteger()
                );

                java.security.spec.ECParameterSpec spec = new java.security.spec.ECParameterSpec(
                        ellipticCurve,
                        g,
                        ecParameters.getN(),
                        ecParameters.getH().intValue()
                );

                // 解析公钥点
                ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) PublicKeyFactory.createKey(sPublicKeyInfo1);
                ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(
                        new ECPoint(
                                publicKeyParameters.getQ().getAffineXCoord().toBigInteger(),
                                publicKeyParameters.getQ().getAffineYCoord().toBigInteger()
                        ),
                        spec
                );
                return keyFactory.generatePublic(ecPublicKeySpec);
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    /**
     * 将私钥字符串还原为 PrivateKey 对象
     *
     * @param algorithm     算法名称
     * @param privateKeyStr 私钥字符串（Base64 编码）
     * @return PrivateKey 对象
     * @throws Exception 异常
     */
    public static PrivateKey restorePrivateKey(String algorithm, String privateKeyStr) throws Exception {
        byte[] keyBytes = Base64.decode(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, "BC");
        switch (algorithm) {
            case ALGORITHM_RSA:
            case ALGORITHM_DSA:
            case ALGORITHM_ECDSA:
            case ALGORITHM_ECDH:
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                return keyFactory.generatePrivate(keySpec);
            case ALGORITHM_ELGAMAL:
                PrivateKeyInfo privateKeyInfo1 = PrivateKeyInfo.getInstance(keyBytes);
                ElGamalPrivateKeyParameters privParams = (ElGamalPrivateKeyParameters) PrivateKeyFactory.createKey(privateKeyInfo1);
                return new CustomElGamalPrivateKey(privParams);
            case ALGORITHM_SM2:
                PrivateKeyInfo privateKeyInfo2 = PrivateKeyInfo.getInstance(keyBytes);
                X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");

                // 类型转换
                ECField field = new ECFieldFp(ecParameters.getCurve().getField().getCharacteristic());
                EllipticCurve ellipticCurve = new EllipticCurve(
                        field,
                        ecParameters.getCurve().getA().toBigInteger(),
                        ecParameters.getCurve().getB().toBigInteger()
                );

                // 转换基点 G
                ECPoint g = new ECPoint(
                        ecParameters.getG().getAffineXCoord().toBigInteger(),
                        ecParameters.getG().getAffineYCoord().toBigInteger()
                );

                java.security.spec.ECParameterSpec spec = new java.security.spec.ECParameterSpec(
                        ellipticCurve,
                        g,
                        ecParameters.getN(),
                        ecParameters.getH().intValue()
                );

                // 解析私钥
                ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(privateKeyInfo2);
                ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(
                        privateKeyParameters.getD(),
                        spec
                );

                return keyFactory.generatePrivate(ecPrivateKeySpec);
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }
}