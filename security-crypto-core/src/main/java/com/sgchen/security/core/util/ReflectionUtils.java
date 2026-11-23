package com.sgchen.security.core.util;


import java.lang.reflect.Field;
import java.util.*;

public class ReflectionUtils {

    private ReflectionUtils(){}

    /**
     * 获取类及其所有父类的字段（包括private字段）
     * @param clazz 目标类
     * @return 包含所有字段的List集合
     */
    public static List<Field> getAllFields(Class<?> clazz) {
        List<Field> fieldList = new ArrayList<>();
        Class<?> currentClass = clazz;

        while (currentClass != null && currentClass != Object.class) {
            fieldList.addAll(Arrays.asList(currentClass.getDeclaredFields()));
            currentClass = currentClass.getSuperclass();
        }
        return fieldList;
    }

    /**
     * 获取字段值（包括私有字段）
     * @param field 字段对象
     * @param target 目标对象
     * @return 字段值
     * @throws IllegalAccessException
     */
    public static Object getFieldValue(Field field, Object target)
            throws IllegalAccessException {
        field.setAccessible(true);
        return field.get(target);
    }


    public static boolean isPlainObject(Object obj) {
        if (obj == null) return false;

        Class<?> clazz = obj.getClass();

        // 排除基本类型及其包装类
        if (clazz.isPrimitive() ||
                Number.class.isAssignableFrom(clazz) ||
                clazz == Boolean.class ||
                clazz == Character.class ||
                clazz == String.class) {
            return false;
        }

        // 排除集合和Map
        if (Collection.class.isAssignableFrom(clazz) ||
                Map.class.isAssignableFrom(clazz)) {
            return false;
        }

        // 排除数组
        if (clazz.isArray()) {
            return false;
        }

        // 其他情况视为普通实例类
        return true;
    }

    public static boolean isCollectionOrArray(Object obj) {
        return obj instanceof Collection || obj.getClass().isArray();
    }

}
