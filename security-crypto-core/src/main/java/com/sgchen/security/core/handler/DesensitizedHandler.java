package com.sgchen.security.core.handler;

import cn.hutool.core.util.StrUtil;
import com.sgchen.security.core.annotation.DesensitizedField;
import com.sgchen.security.core.enums.DesensitizedMode;
import com.sgchen.security.core.util.DesensitizeUtil;

import java.lang.reflect.Field;

/**
 * 脱敏处理类，主要是负责对脱敏注解的判断
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
public class DesensitizedHandler {

    private DesensitizedHandler() {
    }


    /**
     * 脱敏处理
     *
     * @param paramEntity 参数实体
     * @throws IllegalAccessException e
     */
    public static void doDesensitized(Object paramEntity) throws IllegalAccessException {
        //获取参数类的class
        Class<?> paramEntityClass = paramEntity.getClass();
        //获取实体类的所有字段值
        Field[] declaredFields = paramEntityClass.getDeclaredFields();
        //遍历字段脱敏
        for (Field declaredField : declaredFields) {
            //判断字段类型是否是字符串，不是字符串直接跳过
            Class<?> fieldType = declaredField.getType();
            if (!String.class.equals(fieldType)) {
                continue;
            }
            //判断字段是否有脱敏注解
            boolean needDesensitized = declaredField.isAnnotationPresent(DesensitizedField.class);
            //不需要脱敏直接跳过
            if (!needDesensitized) {
                continue;
            }
            declaredField.setAccessible(true);
            Object paramValue = declaredField.get(paramEntity);
            //脱敏
            if (paramValue != null && StrUtil.isNotBlank(paramValue.toString())) {
                String paramValueStr = paramValue.toString();
                //获取脱敏注解
                DesensitizedField desensitizedField = declaredField.getAnnotation(DesensitizedField.class);
                //获取脱敏配置的模式
                DesensitizedMode desensitizedMode = desensitizedField.mode();
                //如果是默认模式，根据front和tail的值脱敏
                if (DesensitizedMode.defaultMode == desensitizedMode) {
                    //否则根据配置的脱敏模式脱敏
                    int front = desensitizedField.front();
                    int tail = desensitizedField.tail();
                    //如果头尾位置都大于0，根据脱敏的头尾值脱敏，否则不进行脱敏处理
                    if (front >= 0 && tail >= 0) {
                        declaredField.set(paramEntity, DesensitizeUtil.desensitized(paramValueStr, front, tail));
                    }
                } else {
                    //如果不是默认模式，则根据配置的模式脱敏
                    declaredField.set(paramEntity, DesensitizeUtil.desensitizedByMode(desensitizedMode, paramValueStr));
                }
                declaredField.setAccessible(false);
            }
        }
    }


}
