package com.sgchen.security.core.util;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.sgchen.security.core.annotation.ReqDecryptField;
import com.sgchen.security.core.enums.SecretAlgorithm;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @description 请求解密工具类
 * @author sgchen
 * @date 2025/11/13 10:05
 * @version 1.0
 */
public class RequestDecryptUtil {

    /**
     * 处理加密数据，若为JSON则递归解密指定字段
     * @param encryptedBytes 加密的数据
     * @param reqSecretKey 请求解密key
     * @param encryptEncIV 解密IV
     * @param algorithm 解密算法
     * @param decryptAnnotation 需要解密的字段注解数组
     * @return 解密后的字符串
     * @throws Exception 解密过程中的异常
     */
    public static String processDecryptData(byte[] encryptedBytes,
                                            String reqSecretKey,
                                            String encryptEncIV,
                                            SecretAlgorithm algorithm,
                                            ReqDecryptField[] decryptAnnotation) throws Exception {
        // 读取加密的请求体
        String encryptedContent = new String(encryptedBytes, StandardCharsets.UTF_8);
        return processDecryptData(encryptedContent, reqSecretKey, encryptEncIV, algorithm, decryptAnnotation);
    }

    /**
     * 处理加密数据，若为JSON则递归解密指定字段
     * @param encryptedContent 加密的字符串内容
     * @param reqSecretKey 请求解密key
     * @param encryptEncIV 解密IV
     * @param algorithm 解密算法
     * @param decryptAnnotation 需要解密的字段注解数组
     * @return 解密后的字符串
     * @throws Exception 解密过程中的异常
     */
    public static String processDecryptData(String encryptedContent,
                                            String reqSecretKey,
                                            String encryptEncIV,
                                            SecretAlgorithm algorithm,
                                            ReqDecryptField[] decryptAnnotation) throws Exception {
        // 提取需要解密的字段集合
        Set<String> needDecryptFields = new HashSet<>();
        if (decryptAnnotation != null) {
            for (ReqDecryptField field : decryptAnnotation) {
                needDecryptFields.add(field.field());
            }
        }

        // 尝试判断是否为JSON格式
        if (isJson(encryptedContent)) {
            // 解析为JSON并递归解密指定字段
            if (encryptedContent.startsWith("{")) {
                JSONObject jsonObject = JSON.parseObject(encryptedContent);
                decryptJsonObject(jsonObject, reqSecretKey, encryptEncIV, algorithm, needDecryptFields);
                return jsonObject.toJSONString();
            } else if (encryptedContent.startsWith("[")) {
                JSONArray jsonArray = JSON.parseArray(encryptedContent);
                decryptJsonArray(jsonArray, reqSecretKey, encryptEncIV, algorithm, needDecryptFields);
                return jsonArray.toJSONString();
            }
        }

        // 非JSON格式：如果有指定解密字段则不解密（非JSON无法区分字段），否则直接解密
        return needDecryptFields.isEmpty() ?
                CryptoSymmetricUtil.decrypt(encryptedContent, reqSecretKey, encryptEncIV, algorithm) :
                encryptedContent;
    }

    /**
     * 递归解密JSONObject中的指定字段
     * @param jsonObject 需要处理的JSONObject
     * @param secretKey 密钥
     * @param iv 向量
     * @param algorithm 算法
     * @param needDecryptFields 需要解密的字段集合（为空时不解密）
     */
    private static void decryptJsonObject(JSONObject jsonObject,
                                          String secretKey,
                                          String iv,
                                          SecretAlgorithm algorithm,
                                          Set<String> needDecryptFields) {
        // 字段集合为空时直接返回，不进行解密
        if (needDecryptFields.isEmpty()) {
            return;
        }

        for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // 只处理需要解密的字段
            if (value instanceof String && needDecryptFields.contains(key)) {
                // 字符串类型直接解密
                String decryptedValue = CryptoSymmetricUtil.decrypt((String) value, secretKey, iv, algorithm);
                entry.setValue(decryptedValue);
            } else if (value instanceof JSONObject) {
                // 嵌套对象递归处理
                decryptJsonObject((JSONObject) value, secretKey, iv, algorithm, needDecryptFields);
            } else if (value instanceof JSONArray) {
                // 数组类型递归处理
                decryptJsonArray((JSONArray) value, secretKey, iv, algorithm, needDecryptFields);
            }
        }
    }

    /**
     * 递归解密JSONArray中的指定字段
     * @param jsonArray 需要处理的JSONArray
     * @param secretKey 密钥
     * @param iv 向量
     * @param algorithm 算法
     * @param needDecryptFields 需要解密的字段集合（为空时不解密）
     */
    private static void decryptJsonArray(JSONArray jsonArray,
                                         String secretKey,
                                         String iv,
                                         SecretAlgorithm algorithm,
                                         Set<String> needDecryptFields) {
        // 字段集合为空时直接返回，不进行解密
        if (needDecryptFields.isEmpty()) {
            return;
        }

        for (int i = 0; i < jsonArray.size(); i++) {
            Object element = jsonArray.get(i);
            if (element instanceof String) {
                // 字符串元素：JSON数组中的字符串无法对应字段名，不进行解密
            } else if (element instanceof JSONObject) {
                // 数组中的对象递归处理
                decryptJsonObject((JSONObject) element, secretKey, iv, algorithm, needDecryptFields);
            } else if (element instanceof JSONArray) {
                // 嵌套数组递归处理
                decryptJsonArray((JSONArray) element, secretKey, iv, algorithm, needDecryptFields);
            }
        }
    }

    /**
     * 判断字符串是否为JSON格式（对象或数组）
     */
    private static boolean isJson(String content) {
        if (content == null || content.trim().isEmpty()) {
            return false;
        }
        String trimmed = content.trim();
        return trimmed.startsWith("{") && trimmed.endsWith("}")
                || trimmed.startsWith("[") && trimmed.endsWith("]");
    }
}