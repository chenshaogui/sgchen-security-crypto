package com.sgchen.security.transfer.interceptor;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sgchen.security.core.annotation.DesensitizedRequest;
import com.sgchen.security.core.annotation.DesensitizedUnit;
import com.sgchen.security.core.annotation.EncryptController;
import com.sgchen.security.core.annotation.EncryptRequest;
import com.sgchen.security.core.enums.DesensitizedMode;
import com.sgchen.security.core.exception.DataSecurityException;
import com.sgchen.security.core.util.DesensitizeUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.util.Collection;
import java.util.Map;

/**
 * 结果相应数据脱敏
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
@ControllerAdvice
@Slf4j
public class DesensitizedResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        if (returnType.hasMethodAnnotation(EncryptController.class)
                || returnType.hasMethodAnnotation(EncryptRequest.class)) {
            return false;
        }
        return returnType.getMethodAnnotation(DesensitizedRequest.class) != null;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType,
                                  MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request,
                                  ServerHttpResponse response) {
        if (body == null) {
            return null;
        }
        DesensitizedRequest desensitizedRequest = returnType.getMethodAnnotation(DesensitizedRequest.class);
        DesensitizedUnit[] units = {};
        if (desensitizedRequest != null) {
            units = desensitizedRequest.value();
        }
        Object json = null;
        try {
            @SuppressWarnings("rawtypes")
            Map dealResult = JSONObject.parseObject(JSON.toJSONString(body), Map.class);
            if (units.length > 0 && isNeedDesensitized()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> result = processMap(dealResult, units);
                json = result;
            } else {
                json = objectMapper.writeValueAsString(body);
            }
        } catch (Exception e) {
            log.error("结果转json出错", e);
            json = body.toString();
        }
        return json;
    }

    protected boolean isNeedDesensitized(){
        return true;
    }

    private Map<String, Object> processMap(Map<String, Object> map, DesensitizedUnit[] units) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            processField(entry, units);
        }
        return map;
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



