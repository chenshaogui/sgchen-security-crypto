package com.sgchen.security.transfer.filter;


import cn.hutool.extra.spring.SpringUtil;
import com.sgchen.security.core.annotation.ReqDecryptField;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.constant.SecurityConstants;
import com.sgchen.security.core.enums.RequestAsymmetricMode;
import com.sgchen.security.core.enums.RequestSolveMode;
import com.sgchen.security.core.exception.AuthSecurityException;
import com.sgchen.security.core.util.CryptoAsymmetricUtil;
import com.sgchen.security.core.util.CryptoSymmetricUtil;
import com.sgchen.security.core.util.RequestDecryptUtil;
import com.sgchen.security.transfer.rsa.bean.EncryptionSessionInfo;
import com.sgchen.security.transfer.rsa.bean.RsaKeyPairEntity;
import com.sgchen.security.transfer.rsa.service.AsymmetricEncryptionKeyManageService;
import com.sgchen.security.transfer.rsa.service.AsymmetricEncryptionSessionService;
import com.sgchen.security.transfer.util.RequestFilterUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.StreamUtils;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.*;

/**
 * HttpServletRequest，头部信息修改，参数解密
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
public class EncryptHttpServletRequest extends HttpServletRequestWrapper {

    private byte[] decryptedBody;

    //可修改的Headers
    private Map<String, String> headers = new HashMap<>();

    private Map<String, String[]> parameterMap;

    public EncryptHttpServletRequest(HttpServletRequest request,
                                     SecretContext securityConfig) throws Exception {
        super(request);
        RequestMappingHandlerMapping handlerMapping = SpringUtil.getBean(RequestMappingHandlerMapping.class);
        HandlerExecutionChain handler = handlerMapping.getHandler(request);
        if (RequestFilterUtil.hasDecryptAnnotation(handler)) {
            // 获取iv解密字符串,如果请求头部中包含iv，那么优先取请求头的iv
            String encryptEncIV = request.getHeader(SecurityConstants.X_ENC_IV);
            if (StringUtils.isEmpty(encryptEncIV)) {
                encryptEncIV = securityConfig.getReqSecretIV();
            }

            // 获取解密密钥
            String reqSecretKey = securityConfig.getReqSecretKey();
            RequestAsymmetricMode requestAsymmetricMode = securityConfig.getRequestAsymmetricMode();
            if (requestAsymmetricMode != null) {
                switch (requestAsymmetricMode.getKeyTransMode()) {
                    case HEADER:
                        String clientKey = request.getHeader(SecurityConstants.X_ENC_CLIENT_KEY);
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
                        String sessionId = request.getHeader(SecurityConstants.X_ENC_SESSION_ID);
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
            // 解密请求体
            byte[] encrypted = StreamUtils.copyToByteArray(request.getInputStream());
            // 处理字段级加密和脱敏逻辑
            String decryptedStr;
            if(securityConfig.getRequestSolveMode() == RequestSolveMode.FIELD){
                ReqDecryptField[] decryptAnnotation = RequestFilterUtil.getDecryptAnnotation(handler);
                decryptedStr = RequestDecryptUtil.processDecryptData(encrypted, reqSecretKey, encryptEncIV, securityConfig.getReqAlgorithm(), decryptAnnotation);
            }else{
                decryptedStr = CryptoSymmetricUtil.decrypt(new String(encrypted), reqSecretKey, encryptEncIV, securityConfig.getReqAlgorithm());
            }
            if (StringUtils.isNotEmpty(decryptedStr)) {
                this.decryptedBody = decryptedStr.getBytes(StandardCharsets.UTF_8);
            }

            // 处理URL参数解密
            this.parameterMap = new HashMap<>(request.getParameterMap());
            if (!this.parameterMap.isEmpty()) {
                String finalEncryptEncIV = encryptEncIV;
                String finalReqSecretKey = reqSecretKey;
                parameterMap.replaceAll((k, v) -> Arrays.stream(v)
                        .map(s -> CryptoSymmetricUtil.decrypt(s, finalReqSecretKey, finalEncryptEncIV, securityConfig.getReqAlgorithm()))
                        .toArray(String[]::new));
            }
        } else {
            this.decryptedBody = StreamUtils.copyToByteArray(request.getInputStream());
            this.parameterMap = super.getParameterMap();
        }
    }

    public EncryptHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        this.decryptedBody = StreamUtils.copyToByteArray(request.getInputStream());
        this.parameterMap = super.getParameterMap();
    }


    public void addHeader(String name, String value) {
        headers.put(name, value);
    }


    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);

        if (headers.containsKey(name)) {
            value = headers.get(name);
        }

        return value;
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        List<String> names = Collections.list(super.getHeaderNames());
        names.addAll(headers.keySet());
        return Collections.enumeration(names);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        List<String> list = Collections.list(super.getHeaders(name));

        if (headers.containsKey(name)) {
            list.add(headers.get(name));
        }

        return Collections.enumeration(list);
    }

    @Override
    public ServletInputStream getInputStream() {
        return new ByteArrayServletInputStream(this.decryptedBody);
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(this.getInputStream()));
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return parameterMap;
    }

    @Override
    public String getParameter(String name) {
        return parameterMap.containsKey(name) ? parameterMap.get(name)[0] : null;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(parameterMap.keySet());
    }

    @Override
    public String[] getParameterValues(String name) {
        return parameterMap.get(name);
    }

}

