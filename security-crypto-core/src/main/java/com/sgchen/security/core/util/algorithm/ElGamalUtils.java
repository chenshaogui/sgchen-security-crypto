package com.sgchen.security.core.util.algorithm;

import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ElGamal 非对称加密工具类
 * 支持 ElGamal 密钥生成、加密、解密、签名和验证等功能
 */
public class ElGamalUtils {
    static {
        // 注册 Bouncy Castle 安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // 默认密钥长度
    public static final int DEFAULT_KEY_SIZE = 2048;

    // 缓存不同密钥长度的 ElGamal 参数
    private static final Map<Integer, ElGamalParameters> ELGAMAL_PARAMS_CACHE = new ConcurrentHashMap<>();

    /**
     * 生成 ElGamal 密钥对
     * @param keySize 密钥长度，推荐值：1024、2048、4096
     * @return 包含公钥和私钥的密钥对
     * @throws Exception 生成过程中可能发生的异常
     */
    public static KeyPair generateKeyPair(int keySize) throws Exception {
        // 使用预生成的 ElGamal 参数
        ElGamalParameters params = getCachedElGamalParameters(keySize);

        // 生成密钥对
        ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
        keyPairGenerator.init(new ElGamalKeyGenerationParameters(new SecureRandom(), params));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 转换为 JCE 兼容格式
        ElGamalPublicKeyParameters pubParams = (ElGamalPublicKeyParameters) keyPair.getPublic();
        ElGamalPrivateKeyParameters privParams = (ElGamalPrivateKeyParameters) keyPair.getPrivate();

        // 创建自定义的 ElGamal 密钥类
        PublicKey publicKey = new CustomElGamalPublicKey(pubParams);
        PrivateKey privateKey = new CustomElGamalPrivateKey(privParams);

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * 使用公钥加密数据
     * @param publicKey 公钥
     * @param plaintext 明文数据
     * @return 加密后的字节数组
     * @throws Exception 加密过程中可能发生的异常
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
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

    /**
     * 使用私钥解密数据
     * @param privateKey 私钥
     * @param ciphertext 密文数据
     * @return 解密后的字节数组
     * @throws Exception 解密过程中可能发生的异常
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) throws Exception {
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

    /**
     * 将公钥编码为 Base64 字符串
     * @param publicKey 公钥
     * @return Base64 编码的公钥字符串
     */
    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.toBase64String(publicKey.getEncoded());
    }

    /**
     * 将私钥编码为 Base64 字符串
     * @param privateKey 私钥
     * @return Base64 编码的私钥字符串
     */
    public static String encodePrivateKey(PrivateKey privateKey) {
        return Base64.toBase64String(privateKey.getEncoded());
    }

    /**
     * 从 Base64 字符串解码为公钥
     * @param publicKeyBase64 Base64 编码的公钥字符串
     * @return 公钥对象
     * @throws Exception 解码过程中可能发生的异常
     */
    public static PublicKey decodePublicKey(String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("ElGamal", "BC");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * 从 Base64 字符串解码为私钥
     * @param privateKeyBase64 Base64 编码的私钥字符串
     * @return 私钥对象
     * @throws Exception 解码过程中可能发生的异常
     */
    public static PrivateKey decodePrivateKey(String privateKeyBase64) throws Exception {
        byte[] keyBytes = Base64.decode(privateKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("ElGamal", "BC");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // 获取缓存的 ElGamal 参数，如果不存在则生成并缓存
    private static ElGamalParameters getCachedElGamalParameters(int keySize) throws Exception {
        return ELGAMAL_PARAMS_CACHE.computeIfAbsent(keySize, k -> {
            try {
                System.out.println("生成 ElGamal 参数，密钥长度: " + k + " 位，这可能需要一些时间...");
                long startTime = System.currentTimeMillis();

                // 生成 ElGamal 参数
                ElGamalParametersGenerator paramGen = new ElGamalParametersGenerator();
                paramGen.init(k, 10, new SecureRandom());
                ElGamalParameters params = paramGen.generateParameters();

                long elapsedTime = System.currentTimeMillis() - startTime;
                System.out.println("ElGamal 参数生成完成，耗时: " + (elapsedTime / 1000) + " 秒");

                return params;
            } catch (Exception e) {
                throw new RuntimeException("生成 ElGamal 参数失败", e);
            }
        });
    }

    // 自定义 ElGamal 公钥实现（使用 DHPublicKey 接口）
    private static class CustomElGamalPublicKey implements DHPublicKey {
        private final ElGamalPublicKeyParameters params;
        private final byte[] encoded;

        public CustomElGamalPublicKey(ElGamalPublicKeyParameters params) {
            this.params = params;
            try {
                // 编码公钥
//                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);
//                this.encoded = publicKeyInfo.getEncoded();
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
//                org.bouncycastle.asn1.pkcs.PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(params);
//                this.encoded = privateKeyInfo.getEncoded();
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

            org.bouncycastle.asn1.pkcs.PrivateKeyInfo privateKeyInfo =
                    new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(algId, asn1X);

            return privateKeyInfo.getEncoded();
        }
    }

    /**
     * 示例用法
     */
    public static void main(String[] args) {
        try {
            // 生成密钥对
            KeyPair keyPair = generateKeyPair(256);
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 待加密的明文
            String plaintext = "Hello, ElGamal加密测试!";
            System.out.println("明文: " + plaintext);

            // 加密
            byte[] ciphertext = encrypt(publicKey, plaintext.getBytes(StandardCharsets.UTF_8));
            System.out.println("加密后(Base64): " + Base64.toBase64String(ciphertext));

            // 解密
            byte[] decrypted = decrypt(privateKey, ciphertext);
            System.out.println("解密后: " + new String(decrypted, StandardCharsets.UTF_8));

            // 公钥和私钥的编码与解码测试
            String publicKeyBase64 = encodePublicKey(publicKey);
            String privateKeyBase64 = encodePrivateKey(privateKey);

            PublicKey decodedPublicKey = decodePublicKey(publicKeyBase64);
            PrivateKey decodedPrivateKey = decodePrivateKey(privateKeyBase64);

            // 使用解码后的密钥进行加密解密测试
            byte[] ciphertext2 = encrypt(decodedPublicKey, plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] decrypted2 = decrypt(decodedPrivateKey, ciphertext2);
            System.out.println("解码后密钥测试: " + new String(decrypted2, StandardCharsets.UTF_8));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}