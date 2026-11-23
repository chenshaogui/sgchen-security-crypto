package com.sgchen.security.core.util;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.sgchen.security.core.enums.DesensitizedMode;

import java.util.*;
import java.util.regex.Pattern;

/**
 * JSON数据脱敏工具类，基于Gson处理JsonObject对象
 */
public class JsonDesensitizationUtil {

    /**
     * 预定义的敏感字段与脱敏类型映射
     */
    private static final Map<String, DesensitizedMode> FIELD_TYPE_MAPPING = new HashMap<>();


    /**
     * 对JsonObject进行脱敏处理，使用自定义配置
     *
     * @param jsonObject 要脱敏的JsonObject
     * @param config     自定义配置
     * @return 脱敏后的JsonObject
     */
    public static JSONObject desensitize(JSONObject jsonObject, Config config) {
        if (jsonObject == null) {
            return null;
        }

        if (config == null) {
            config = new Config();
        }

        Set<Map.Entry<String, Object>> entries = jsonObject.entrySet();

        for (Map.Entry<String, Object> entry : entries) {
            String key = entry.getKey();
            Object value = entry.getValue();
            // 检查是否需要脱敏
            if (shouldDesensitize(key, config)) {
                DesensitizedMode type = getDesensitizedMode(key, config);
                String customRule = config.getCustomRule(key);

                if (value instanceof String) {
                    String originalValue = value.toString();
                    String desensitizedValue = desensitizeString(originalValue, type, customRule);
                    jsonObject.put(key, desensitizedValue);
                } else {
                    // 非字符串类型，递归处理
                    jsonObject.put(key, desensitizeElement(value, config));
                }
            }
            // 不需要脱敏，递归处理
            else {
                jsonObject.put(key, desensitizeElement(value, config));
            }
        }
        return jsonObject;
    }

    /**
     * 对JsonElement进行脱敏处理
     */
    private static Object desensitizeElement(Object element, Config config) {
        if (element == null) {
            return null;
        }

        if (element instanceof JSONObject) {
            return desensitize((JSONObject) element, config);
        } else if (element instanceof JSONArray) {
            JSONArray result = (JSONArray) element;
            JSONArray newResult = new JSONArray();
            for (Object item : result) {
                newResult.add(desensitizeElement(item, config));
            }
            return newResult;
        } else {
            // 基本类型，直接返回
            return element;
        }
    }

    /**
     * 判断是否应该对字段进行脱敏
     */
    private static boolean shouldDesensitize(String key, Config config) {
        // 如果配置了强制脱敏列表，优先检查
        if (config.getForceDesensitizeFields() != null &&
                config.getForceDesensitizeFields().contains(key)) {
            return true;
        }

        // 如果配置了排除列表，不脱敏
        if (config.getExcludeFields() != null &&
                config.getExcludeFields().contains(key)) {
            return false;
        }

        // 检查是否匹配敏感字段正则表达式
        if (config.getSensitiveFieldPattern() != null &&
                config.getSensitiveFieldPattern().matcher(key).matches()) {
            return true;
        }

        if (config.getFieldTypeMapping() != null &&
                config.getFieldTypeMapping().containsKey(key)) {
            return true;
        }

        return false;
    }

    /**
     * 获取字段的脱敏类型
     */
    private static DesensitizedMode getDesensitizedMode(String key, Config config) {
        // 优先使用配置中的映射
        if (config.getFieldTypeMapping() != null &&
                config.getFieldTypeMapping().containsKey(key)) {
            return config.getFieldTypeMapping().get(key);
        }

        // 使用预定义的映射
        if (FIELD_TYPE_MAPPING.containsKey(key.toLowerCase())) {
            return FIELD_TYPE_MAPPING.get(key.toLowerCase());
        }

        // 默认脱敏类型
        return DesensitizedMode.defaultMode;
    }

    /**
     * 对字符串进行脱敏
     */
    private static String desensitizeString(String value, DesensitizedMode type, String customRule) {
        if (value == null || value.trim().isEmpty()) {
            return value;
        }

        String result;
        switch (type) {
            case name:
                result = desensitizeName(value);
                break;
            case mobile:
                result = desensitizePhone(value);
                break;
            case idCard:
                result = desensitizeIdCard(value);
                break;
            case bankCard:
                result = desensitizeBankCard(value);
                break;
            case email:
                result = desensitizeEmail(value);
                break;
            case address:
                result = desensitizeAddress(value);
                break;
            case defaultMode:
            default:
                result = desensitizeDefault(value);
                break;
        }
        return result;
    }

    /**
     * 默认脱敏：保留前后各3位，中间用*替换
     */
    private static String desensitizeDefault(String value) {
        int length = value.length();
        if (length <= 6) {
            return value.charAt(0) + String.join("", Collections.nCopies(length - 2, "*")) +
                    (length >= 2 ? value.charAt(length - 1) : "");
        }
        return value.substring(0, 3) + String.join("", Collections.nCopies(length - 6, "*")) +
                value.substring(length - 3);
    }

    /**
     * 姓名脱敏：保留姓氏，名字用*替换
     */
    private static String desensitizeName(String value) {
        if (value.length() <= 1) {
            return value;
        }
        return value.charAt(0) + String.join("", Collections.nCopies(value.length() - 1, "*"));
    }

    /**
     * 手机号脱敏：保留前3位和后4位，中间用*替换
     */
    private static String desensitizePhone(String value) {
        if (value.length() != 11) {
            return desensitizeDefault(value);
        }
        return value.substring(0, 3) + "****" + value.substring(7);
    }

    /**
     * 身份证号脱敏：保留前6位和后4位，中间用*替换
     */
    private static String desensitizeIdCard(String value) {
        if (value.length() < 18) {
            return desensitizeDefault(value);
        }
        return value.substring(0, 6) + String.join("", Collections.nCopies(8, "*")) +
                value.substring(14);
    }

    /**
     * 银行卡号脱敏：保留前4位和后4位，中间用*替换
     */
    private static String desensitizeBankCard(String value) {
        if (value.length() < 8) {
            return desensitizeDefault(value);
        }
        return value.substring(0, 4) + String.join("", Collections.nCopies(value.length() - 8, "*")) +
                value.substring(value.length() - 4);
    }

    /**
     * 邮箱脱敏：保留前缀前3位和后缀，中间用*替换
     */
    private static String desensitizeEmail(String value) {
        int atIndex = value.indexOf("@");
        if (atIndex <= 3 || atIndex >= value.length() - 1) {
            return desensitizeDefault(value);
        }
        String prefix = value.substring(0, 3);
        String suffix = value.substring(atIndex);
        return prefix + String.join("", Collections.nCopies(atIndex - 3, "*")) + suffix;
    }

    /**
     * 地址脱敏：保留省市区，详细地址用*替换
     */
    private static String desensitizeAddress(String value) {
        // 简化处理，实际应用中可以根据行政区划规则更精确地脱敏
        String[] parts = value.split("[省|市|区|县]");
        if (parts.length > 1) {
            return parts[0] + parts[1] + "**" + (parts.length > 2 ? parts[2] : "");
        }
        return desensitizeDefault(value);
    }

    /**
     * 自定义规则脱敏
     */
    private static String desensitizeByCustomRule(String value, String customRule) {
        if (customRule == null || customRule.isEmpty()) {
            return desensitizeDefault(value);
        }

        String[] rules = customRule.split("_");
        if (rules.length != 3) {
            return desensitizeDefault(value);
        }

        try {
            int prefixLength = Integer.parseInt(rules[0]);
            int suffixLength = Integer.parseInt(rules[1]);
            String replaceChar = rules[2];

            int length = value.length();
            if (length <= prefixLength + suffixLength) {
                return value.charAt(0) + String.join("", Collections.nCopies(length - 2, replaceChar)) +
                        (length >= 2 ? value.charAt(length - 1) : "");
            }

            return value.substring(0, prefixLength) +
                    String.join("", Collections.nCopies(length - prefixLength - suffixLength, replaceChar)) +
                    value.substring(length - suffixLength);
        } catch (NumberFormatException e) {
            return desensitizeDefault(value);
        }
    }

    /**
     * 配置类，用于自定义脱敏行为
     */
    public static class Config {
        private Set<String> forceDesensitizeFields;
        private Set<String> excludeFields;
        private Map<String, DesensitizedMode> fieldTypeMapping;
        private Map<String, String> customRules;
        private Pattern sensitiveFieldPattern;

        public Config() {
        }

        public Set<String> getForceDesensitizeFields() {
            return forceDesensitizeFields;
        }

        public Config setForceDesensitizeFields(Set<String> forceDesensitizeFields) {
            this.forceDesensitizeFields = forceDesensitizeFields;
            return this;
        }

        public Set<String> getExcludeFields() {
            return excludeFields;
        }

        public Config setExcludeFields(Set<String> excludeFields) {
            this.excludeFields = excludeFields;
            return this;
        }

        public Map<String, DesensitizedMode> getFieldTypeMapping() {
            return fieldTypeMapping;
        }

        public Config setFieldTypeMapping(Map<String, DesensitizedMode> fieldTypeMapping) {
            this.fieldTypeMapping = fieldTypeMapping;
            return this;
        }

        public String getCustomRule(String fieldName) {
            return customRules != null ? customRules.get(fieldName) : null;
        }

        public Config setCustomRules(Map<String, String> customRules) {
            this.customRules = customRules;
            return this;
        }

        public Pattern getSensitiveFieldPattern() {
            return sensitiveFieldPattern;
        }

        public Config setSensitiveFieldPattern(Pattern sensitiveFieldPattern) {
            this.sensitiveFieldPattern = sensitiveFieldPattern;
            return this;
        }

        // 便捷方法：添加强制脱敏字段
        public Config addForceDesensitizeField(String field) {
            if (forceDesensitizeFields == null) {
                forceDesensitizeFields = new HashSet<>();
            }
            forceDesensitizeFields.add(field);
            return this;
        }

        // 便捷方法：添加排除字段
        public Config addExcludeField(String field) {
            if (excludeFields == null) {
                excludeFields = new HashSet<>();
            }
            excludeFields.add(field);
            return this;
        }

        // 便捷方法：添加字段脱敏类型映射
        public Config addFieldTypeMapping(String field, DesensitizedMode type) {
            if (fieldTypeMapping == null) {
                fieldTypeMapping = new HashMap<>();
            }
            fieldTypeMapping.put(field, type);
            return this;
        }

        // 便捷方法：添加自定义脱敏规则
        public Config addCustomRule(String field, String rule) {
            if (customRules == null) {
                customRules = new HashMap<>();
            }
            customRules.put(field, rule);
            return this;
        }
    }

    /**
     * 示例用法
     */
    public static void main(String[] args) {
        // 创建示例JSON
        JSONObject json = new JSONObject();
        json.put("id", 1);
        json.put("name", "张三");
        json.put("phone", "13812345678");
        json.put("idCard", "110101199001011234");
        json.put("email", "zhangsan@example.com");
        json.put("address", "北京市朝阳区建国路88号");

        // 添加嵌套对象和数组
        JSONObject nestedObj = new JSONObject();
        nestedObj.put("bankCard", "6222021234567890123");
        json.put("financialInfo", nestedObj);

        JSONArray array = new JSONArray();
        JSONObject item1 = new JSONObject();
        item1.put("name", "李四");
        item1.put("phone", "13987654321");
        array.add(item1);
        json.put("friends", array);

        System.out.println("原始JSON:");
        System.out.println(json.toString());

        // 使用自定义配置脱敏
        Config config = new Config()
                .addFieldTypeMapping("name", DesensitizedMode.name)
                .addFieldTypeMapping("phone", DesensitizedMode.mobile)
                .addFieldTypeMapping("idCard", DesensitizedMode.idCard)
                .addFieldTypeMapping("address", DesensitizedMode.address)
                .addFieldTypeMapping("bankCard", DesensitizedMode.bankCard);

        JSONObject customDesensitizedJson = desensitize(json, config);
        System.out.println("\n自定义配置脱敏后JSON:");
        System.out.println(customDesensitizedJson.toString());
    }
}