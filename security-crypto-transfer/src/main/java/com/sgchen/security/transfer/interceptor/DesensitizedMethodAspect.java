package com.sgchen.security.transfer.interceptor;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.sgchen.security.core.annotation.DesensitizedMethod;
import com.sgchen.security.core.annotation.DesensitizedUnit;
import com.sgchen.security.core.enums.DesensitizedMode;
import com.sgchen.security.core.exception.DataSecurityException;
import com.sgchen.security.core.util.DesensitizeUtil;
import com.sgchen.security.core.util.ReflectionUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Map;

@Aspect
@Component
@Slf4j
public class DesensitizedMethodAspect {

    @Around("@annotation(com.sgchen.security.annotation.DesensitizedMethod)")
    public Object around(ProceedingJoinPoint joinPoint) throws Throwable {
        // 执行原方法
        Object result = joinPoint.proceed();

        if (result == null) {
            return null;
        }
        // 获取方法上的注解
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        DesensitizedMethod desensitize = method.getAnnotation(DesensitizedMethod.class);
        DesensitizedUnit[] units = {};
        if (desensitize != null) {
            units = desensitize.value();
        }
        if(units.length==0){
            return result;
        }
        if(result instanceof Map){
            processMap((Map)result, units);
        }
        if(ReflectionUtils.isPlainObject(result)){
            Map parsed = JSONObject.parseObject(JSONObject.toJSONString(result), Map.class);
            processMap(parsed, units);
            result = JSONObject.parseObject(JSONObject.toJSONString(parsed), result.getClass());
        }
        if(result instanceof Collection){
            Collection<?> collList = (Collection)result;
            JSONArray jsonArr = JSONArray.parseArray(JSONArray.toJSONString(collList));
            for (Object item : jsonArr) {
                if(item instanceof Map){
                    processMap((Map)item, units);
                }
            }
            result = jsonArr;
        }
        return result;
    }

    private void processMap(Map<String, Object> map, DesensitizedUnit[] units) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            processField(entry, units);
        }
    }

    private void processField(Map.Entry<String, Object> entry, DesensitizedUnit[] units) {
        if (entry.getValue() instanceof Map) {
            //noinspection unchecked
            processMap((Map<String, Object>) entry.getValue(), units);
        } else if (entry.getValue() instanceof Collection) {
            @SuppressWarnings("rawtypes")
            Collection valList = (Collection) entry.getValue();
            for (Object valItem : valList) {
                if (valItem instanceof Map) {
                    //noinspection unchecked
                    processMap((Map<String, Object>) valItem, units);
                }
            }
        } else if (entry.getValue() instanceof String
                && entry.getKey() != null) {
            applySensitiveRule(entry, units);
        }
    }

    private void applySensitiveRule(Map.Entry<String, Object> entry, DesensitizedUnit[] units) {
        try {
            for (DesensitizedUnit unit : units) {
                if (StringUtils.equals(unit.field(), entry.getKey())) {
                    DesensitizedMode desensitizedMode = unit.mode();
                    //如果是默认模式，根据front和tail的值脱敏
                    if (DesensitizedMode.defaultMode == desensitizedMode) {
                        //否则根据配置的脱敏模式脱敏
                        int front = unit.front();
                        int tail = unit.tail();
                        //如果头尾位置都大于0，根据脱敏的头尾值脱敏，否则不进行脱敏处理
                        if (front >= 0 && tail >= 0) {
                            entry.setValue(DesensitizeUtil.desensitized(entry.getValue().toString(), front, tail));
                        }
                    } else {
                        //如果不是默认模式，则根据配置的模式脱敏
                        entry.setValue(DesensitizeUtil.desensitizedByMode(desensitizedMode, entry.getValue().toString()));
                    }
                }
            }
        } catch (Exception e) {
            // 忽略处理异常
            log.error("字段脱敏发生错误", e);
            throw new DataSecurityException("字段脱敏异常");
        }
    }

}
