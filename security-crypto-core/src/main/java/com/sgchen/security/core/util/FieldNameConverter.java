package com.sgchen.security.core.util;

public class FieldNameConverter {

    // 转换策略枚举
    public enum CaseFormat {
        /**
         * 下划线转驼峰
         */
        UNDERSCORE_TO_CAMEL,
        /**
         * 驼峰转下划线
         */
        CAMEL_TO_UNDERSCORE
    }

    public static String convert(String columnName, CaseFormat format) {
        // 执行格式转换
        switch (format) {
            case UNDERSCORE_TO_CAMEL:
                return underScoreToCamel(columnName);
            case CAMEL_TO_UNDERSCORE:
                return camelToUnderScore(columnName);
            default:
                return columnName;
        }
    }


    /**
     * 将字符串驼峰转为字符串
     *
     * @param str 转换数据
     * @return 转换结果
     */
    public static String camelToUnderScore(String str) {
        if (str == null || str.isEmpty()) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        result.append(Character.toLowerCase(str.charAt(0)));
        for (int i = 1; i < str.length(); i++) {
            char c = str.charAt(i);
            if (Character.isUpperCase(c)) {
                result.append('_');
                result.append(Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * 将字符串的下划线转为驼峰
     *
     * @param str 转换数据
     * @return 转换结果
     */
    public static String underScoreToCamel(String str) {
        if (str == null || str.isEmpty()) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        boolean nextUpper = false;

        for (int i = 0; i < str.length(); i++) {
            char current = str.charAt(i);
            if (current == '_') {
                nextUpper = true;
            } else {
                if (nextUpper) {
                    result.append(Character.toUpperCase(current));
                    nextUpper = false;
                } else {
                    result.append(Character.toLowerCase(current));
                }
            }
        }
        return result.toString();
    }


}