package com.sgchen.security.transfer.interceptor;

import cn.hutool.core.date.DateUtil;
import cn.hutool.extra.spring.SpringUtil;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import com.sgchen.security.core.annotation.DesensitizedRequest;
import com.sgchen.security.core.annotation.DesensitizedUnit;
import com.sgchen.security.core.annotation.EncryptController;
import com.sgchen.security.core.annotation.EncryptRequest;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.constant.SecurityConstants;
import com.sgchen.security.core.enums.DesensitizedMode;
import com.sgchen.security.core.enums.RequestAsymmetricMode;
import com.sgchen.security.core.enums.RequestSolveMode;
import com.sgchen.security.core.exception.AuthSecurityException;
import com.sgchen.security.core.exception.DataSecurityException;
import com.sgchen.security.core.util.CryptoAsymmetricUtil;
import com.sgchen.security.core.util.CryptoSymmetricUtil;
import com.sgchen.security.core.util.DesensitizeUtil;
import com.sgchen.security.core.util.ResponseEncryptUtil;
import com.sgchen.security.transfer.rsa.bean.EncryptionSessionInfo;
import com.sgchen.security.transfer.rsa.bean.RsaKeyPairEntity;
import com.sgchen.security.transfer.rsa.service.AsymmetricEncryptionKeyManageService;
import com.sgchen.security.transfer.rsa.service.AsymmetricEncryptionSessionService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.PrivateKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

/**
 * 结果相应数据解密+脱敏
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
@RestControllerAdvice
//@ConditionalOnNoSubclass(EncryptRestControllerAdvice.class)
@Slf4j
@Order(Ordered.LOWEST_PRECEDENCE)
@ConditionalOnProperty(
        prefix = "csg-security.request",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class EncryptRestControllerAdvice implements ResponseBodyAdvice<Object> {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean supports(MethodParameter returnType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        if (returnType.hasMethodAnnotation(EncryptRequest.class)
                || returnType.hasMethodAnnotation(DesensitizedRequest.class)) {
            return false;
        }
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            HttpServletRequest request = attributes.getRequest();
            // 如果是Feign调用，跳过拦截
            if ("true".equals(request.getHeader(SecurityConstants.FEIGN_CLIENT_CALL))) {
                return false;
            }
        }
        return returnType.getContainingClass().isAnnotationPresent(EncryptController.class);
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
        SecretContext secretConfig = null;
        try {
            secretConfig = SpringUtil.getBean(SecretContext.class);
        } catch (Exception e) {
            log.warn("秘钥未配置，返回结果加密放行");
            return body;
        }
        EncryptController encryptRequest = returnType.getContainingClass().getAnnotation(EncryptController.class);
        DesensitizedUnit[] units = {};
        if (encryptRequest != null) {
            units = encryptRequest.value();
        }

        String reqSecretIV = secretConfig.getReqSecretIV();
        // 如果是CBC模式，并且配置中IV是空的。生成动态IV
        if (secretConfig.getReqAlgorithm() != null
                && secretConfig.getReqAlgorithm().getEncryptAlgorithm().contains("CBC")
                && StringUtils.isEmpty(reqSecretIV)) {
            String firstIV = request.getHeaders().getFirst(SecurityConstants.X_ENC_IV);
            if (StringUtils.isNotEmpty(firstIV)) {
                byte[] hexCode = null;
                byte[] base64Code = null;

                // 尝试Hex解码
                try {
                    hexCode = Hex.decode(firstIV);
                } catch (DecoderException e) {
                    // 记录日志但继续执行，尝试Base64解码
                    // log.warn("Failed to decode IV as Hex: {}", firstIV, e);
                }

                // 尝试Base64解码
                try {
                    base64Code = Base64.decode(firstIV);
                } catch (IllegalArgumentException e) {
                    // 记录日志但继续执行
                    // log.warn("Failed to decode IV as Base64: {}", firstIV, e);
                }

                int expectedSize = secretConfig.getReqAlgorithm().getIvSize();

                // 根据解码结果和长度验证选择IV
                if (hexCode != null && hexCode.length == expectedSize) {
                    reqSecretIV = CryptoSymmetricUtil.generateIvHex(secretConfig.getReqAlgorithm());
                } else if (base64Code != null && base64Code.length == expectedSize) {
                    reqSecretIV = CryptoSymmetricUtil.generateIVBase64(secretConfig.getReqAlgorithm());
                } else {
                    /*// 无法解码或长度不匹配时的默认处理
                    log.error("Invalid IV format or size. Expected size: {}, IV: {}",
                            expectedSize, firstIV);
                    // 可以选择抛出业务异常或使用默认IV
                    throw new SecurityException("Invalid encryption IV");*/
                    reqSecretIV = firstIV;
                }
            }
            response.getHeaders().set(SecurityConstants.X_ENC_IV, reqSecretIV);
        }
        // 获取解密密钥
        String reqSecretKey = secretConfig.getReqSecretKey();
        RequestAsymmetricMode requestAsymmetricMode = secretConfig.getRequestAsymmetricMode();
        if (requestAsymmetricMode != null) {
            switch (requestAsymmetricMode.getKeyTransMode()) {
                case HEADER:
                    String clientKey = request.getHeaders().getFirst(SecurityConstants.X_ENC_CLIENT_KEY);
                    if (StringUtils.isEmpty(clientKey)) {
                        throw new AuthSecurityException("非对称客户端私钥请求头模式缺少：" + SecurityConstants.X_ENC_CLIENT_KEY);
                    }
                    // 使用公钥解密客户端私钥
                    try {
                        AsymmetricEncryptionKeyManageService keyManageService = SpringUtil.getBean(AsymmetricEncryptionKeyManageService.class);
                        RsaKeyPairEntity currentRsaPairKey = keyManageService.getLatestKeyPair();
                        if (currentRsaPairKey == null) {
                            throw new AuthSecurityException("公钥已过期");
                        }
                        PrivateKey privateKey = CryptoAsymmetricUtil.restorePrivateKey(currentRsaPairKey.getPrivateKey(), requestAsymmetricMode);
                        reqSecretKey = CryptoAsymmetricUtil.decryptWithPrivateKey(clientKey, privateKey, requestAsymmetricMode);
                    } catch (Exception e) {
                        throw new AuthSecurityException(e.getMessage());
                    }
                    break;
                case SESSION:
                    String sessionId = request.getHeaders().getFirst(SecurityConstants.X_ENC_SESSION_ID);
                    if (StringUtils.isEmpty(sessionId)) {
                        throw new AuthSecurityException("非对称客户端会话模式缺少：" + SecurityConstants.X_ENC_SESSION_ID);
                    }
                    // 使用公钥解密客户端私钥
                    try {
                        AsymmetricEncryptionSessionService sessionService = SpringUtil.getBean(AsymmetricEncryptionSessionService.class);
                        EncryptionSessionInfo sessionInfo = sessionService.getSessionInfo(sessionId);
                        reqSecretKey = sessionInfo.getClientKey();
                    } catch (Exception e) {
                        throw new AuthSecurityException(e.getMessage());
                    }
                    break;
            }
        }
        // 处理字段级加密和脱敏逻辑
        if(secretConfig.getRequestSolveMode() == RequestSolveMode.FIELD){
            // 增加一个工具类，先对有注解的units脱敏，再判断返回的对象有没有包含@RspEncryptEntity注解，
            //  如果存在就只对@RspEncryptField注解的字段加密，以及其他的模式补充
            return ResponseEncryptUtil.encryptRspData(body, returnType, units, reqSecretIV, reqSecretKey, secretConfig);
        }

        String json = null;
        SimpleModule module = new SimpleModule();
        module.addSerializer(Long.class, ToStringSerializer.instance);
        module.addSerializer(Date.class, new JsonSerializer<Date>() {
            @Override
            public void serialize(Date value, JsonGenerator gen, SerializerProvider provider)
                    throws IOException {
                gen.writeString(DateUtil.format(value, "yyyy-MM-dd HH:mm:ss"));
            }
        });
        module.addSerializer(LocalDateTime.class, new LocalDateTimeSerializer(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        ));
        objectMapper.registerModule(module);
        try {
            @SuppressWarnings("rawtypes")
            Map dealResult = JSONObject.parseObject(JSON.toJSONString(body), Map.class);
            if (units.length > 0 && isNeedDesensitized()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> result = processMap(dealResult, units);
                json = objectMapper.writeValueAsString(result);
            } else {
                json = objectMapper.writeValueAsString(body);
            }
        } catch (Exception e) {
            log.error("响应结果转JSON出错", e);
            json = body.toString();
        }

        return CryptoSymmetricUtil.encrypt(json, reqSecretKey, reqSecretIV, secretConfig.getReqAlgorithm());
    }

    protected boolean isNeedDesensitized() {
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



