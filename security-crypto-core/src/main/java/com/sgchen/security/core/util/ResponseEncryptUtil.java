package com.sgchen.security.core.util;


import com.sgchen.security.core.annotation.DesensitizedUnit;
import com.sgchen.security.core.annotation.RspEncryptEntity;
import com.sgchen.security.core.annotation.RspEncryptField;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.enums.DesensitizedMode;
import com.sgchen.security.core.enums.SecretAlgorithm;
import com.sgchen.security.core.exception.DataSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Map;

/**
 * @author sgchen
 * @version 1.0
 * @description 响应加密工具类
 * @date 2025/11/13 10:05
 */
public class ResponseEncryptUtil {

    private static final Logger logger = LoggerFactory.getLogger(ResponseEncryptUtil.class);

    public static Object encryptRspData(Object body,
                                     MethodParameter returnType,
                                     DesensitizedUnit[] units,
                                     String reqSecretIV,
                                     String reqSecretKey,
                                     SecretContext secretConfig) {
        // 处理字段级加密和脱敏逻辑
        Object desensitizedBody = processDesensitization(body, units);
        return processFieldEncryption(desensitizedBody, reqSecretKey, reqSecretIV, secretConfig.getReqAlgorithm());
    }

    /**
     * 处理对象的脱敏逻辑
     */
    private static Object processDesensitization(Object body, DesensitizedUnit[] units) {
        if (units.length == 0 || body == null) {
            return body;
        }

        try {
            // 处理集合类型
            if (body instanceof Collection) {
                Collection<?> collection = (Collection<?>) body;
                for (Object item : collection) {
                    processObjectDesensitization(item, units);
                }
                return collection;
            }
            // 处理单个对象
            return processObjectDesensitization(body, units);
        } catch (Exception e) {
            logger.error("脱敏处理失败", e);
            throw new DataSecurityException("脱敏处理异常");
        }
    }

    /**
     * 处理单个对象的脱敏
     */
    private static Object processObjectDesensitization(Object obj, DesensitizedUnit[] units) throws IllegalAccessException {
        if (obj == null || obj.getClass().isPrimitive() || obj instanceof String) {
            return obj;
        }

        // 反射处理对象字段ReflectionUtils.getAllFields(obj.getClass())
        for (Field field : ReflectionUtils.getAllFields(obj.getClass())) {
            field.setAccessible(true);
            Object fieldValue = field.get(obj);

            // 处理嵌套对象
            if (fieldValue != null && !fieldValue.getClass().isPrimitive()
                    && !(fieldValue instanceof String) && !(fieldValue instanceof Collection)) {
                processObjectDesensitization(fieldValue, units);
            }

            // 处理集合元素
            if (fieldValue instanceof Collection) {
                for (Object item : (Collection<?>) fieldValue) {
                    processObjectDesensitization(item, units);
                }
            }

            // 应用脱敏规则
            applyFieldSensitiveRule(field, obj, fieldValue, units);
        }
        return obj;
    }

    /**
     * 对字段应用脱敏规则
     */
    private static void applyFieldSensitiveRule(Field field, Object obj, Object fieldValue, DesensitizedUnit[] units)
            throws IllegalAccessException {
        if (!(fieldValue instanceof String)) {
            return;
        }

        String fieldName = field.getName();
        for (DesensitizedUnit unit : units) {
            if (unit.field().equals(fieldName)) {
                String desensitizedValue = processDesensitizeValue((String) fieldValue, unit);
                field.set(obj, desensitizedValue);
                break;
            }
        }
    }

    /**
     * 处理脱敏值
     */
    private static String processDesensitizeValue(String value, DesensitizedUnit unit) {
        DesensitizedMode mode = unit.mode();
        if (DesensitizedMode.defaultMode == mode) {
            int front = unit.front();
            int tail = unit.tail();
            if (front >= 0 && tail >= 0) {
                return DesensitizeUtil.desensitized(value, front, tail);
            }
        } else {
            return DesensitizeUtil.desensitizedByMode(mode, value);
        }
        return value;
    }

    /**
     * 处理字段级加密
     */
    private static Object processFieldEncryption(Object body, String secretKey, String iv, SecretAlgorithm algorithm) {
        try {
            if (body instanceof Collection) {
                Collection<?> collection = (Collection<?>) body;
                for (Object item : collection) {
                    processObjectFieldEncryption(item, secretKey, iv, algorithm);
                }
                return collection;
            }
            return processObjectFieldEncryption(body, secretKey, iv, algorithm);
        } catch (Exception e) {
            logger.error("字段加密处理失败", e);
            throw new DataSecurityException("字段加密异常");
        }
    }

    /**
     * 处理单个对象的字段加密
     */
    private static Object processObjectFieldEncryption(Object obj, String secretKey, String iv, SecretAlgorithm algorithm)
            throws IllegalAccessException {
        if (obj == null) {
            return null;
        }

        // 处理Map类型
        if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                Object key = entry.getKey();
                Object value = entry.getValue();

                // 递归处理Map中的值
                if (value != null) {
                    Object processedValue = processObjectFieldEncryption(value, secretKey, iv, algorithm);
                    // 如果是可修改的Map，更新处理后的值
                    if (map instanceof java.util.HashMap) {
                        ((java.util.HashMap<Object, Object>) map).put(key, processedValue);
                    } else if (map instanceof java.util.LinkedHashMap) {
                        ((java.util.LinkedHashMap<Object, Object>) map).put(key, processedValue);
                    }
                }
            }
            return obj;
        }

        for (Field field : ReflectionUtils.getAllFields(obj.getClass())) {
            field.setAccessible(true);
            Object fieldValue = field.get(obj);

            // 处理嵌套对象
            if (fieldValue != null && field.isAnnotationPresent(RspEncryptEntity.class)) {
                processObjectFieldEncryption(fieldValue, secretKey, iv, algorithm);
            }

            // 处理集合元素
            if (fieldValue instanceof Collection) {
                for (Object item : (Collection<?>) fieldValue) {
                    if (item != null) {
                        processObjectFieldEncryption(item, secretKey, iv, algorithm);
                    }
                }
            }

            // 加密标记的字段
            if (field.isAnnotationPresent(RspEncryptField.class) && fieldValue instanceof String) {
                String encryptedValue = CryptoSymmetricUtil.encrypt(
                        (String) fieldValue, secretKey, iv, algorithm);
                field.set(obj, encryptedValue);
            }
        }
        return obj;
    }
}