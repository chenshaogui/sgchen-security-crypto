package com.sgchen.security.transfer.rsa.controller;


import cn.hutool.extra.spring.SpringUtil;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.exception.AuthSecurityException;
import com.sgchen.security.core.exception.DataSecurityException;
import com.sgchen.security.core.util.CryptoAsymmetricUtil;
import com.sgchen.security.transfer.rsa.bean.EncryptClientKeyReq;
import com.sgchen.security.transfer.rsa.bean.EncryptionSessionInfo;
import com.sgchen.security.transfer.rsa.bean.RsaKeyPairEntity;
import com.sgchen.security.transfer.rsa.service.AsymmetricEncryptionKeyManageService;
import com.sgchen.security.transfer.rsa.service.AsymmetricEncryptionSessionService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * 非对称相关控制器
 */
@RestController
@RequestMapping("/api/asymmetricTSC")
@ConditionalOnBean({
        AsymmetricEncryptionKeyManageService.class,
        AsymmetricEncryptionSessionService.class
})
public class AsymmetricEncryptionController {

    @Autowired
    private AsymmetricEncryptionKeyManageService asymmetricEncryptionKeyManageService;

    @Autowired
    private AsymmetricEncryptionSessionService asymmetricEncryptionSessionService;


    @GetMapping("/public-key")
    public Map<String, String> getPublicKey() {
        RsaKeyPairEntity currentRsaPairKey = asymmetricEncryptionKeyManageService.getOrRefreshCurrentRsaPairKey();
        Map<String, String> result = new HashMap<>();
        result.put("publicKey", currentRsaPairKey.getPublicKey());
        result.put("version", currentRsaPairKey.getVersion());
        return result;
    }

    /**
     * 创建加密会话（添加获取客户端IP的逻辑）
     */
    @PostMapping("/create-session")
    public Map<String, Object> createSession(
            @RequestHeader("X-Client-Key") String encryptedClientKey,
            @RequestHeader("X-Timestamp") long timestamp,
            HttpServletRequest request
    ) {
        // 验证时间戳
        if (Math.abs(System.currentTimeMillis() - timestamp) > 60_000) {
            throw new SecurityException("The request has expired.");
        }

        // 获取客户端IP（考虑代理情况）
        String clientIp = getClientIp(request);

        EncryptionSessionInfo sessionInfo = asymmetricEncryptionSessionService.createEncryptedSession(clientIp, encryptedClientKey);

        Map<String, Object> result = new HashMap<>();
        result.put("sessionId", sessionInfo.getSessionId());
        result.put("expiresIn", (sessionInfo.getExpireTime() - System.currentTimeMillis()) / 1000);
        result.put("publicKeyVersion", sessionInfo.getPublicKeyVersion());
        return result;
    }

    @GetMapping("/session-stats")
    public Map<String, Object> getSystemStats() {
        RsaKeyPairEntity latestKeyPair = asymmetricEncryptionKeyManageService.getLatestKeyPair();
        if (latestKeyPair == null) {
            throw new AuthSecurityException("The public key has expired.");
        }
        Map<String, Object> result = new HashMap<>();
        result.put("sessionCount", asymmetricEncryptionSessionService.getSessionCount());
        result.put("keyVersion", latestKeyPair.getVersion());
        return result;
    }

    @PostMapping("/encrypt-client-key")
    public Map<String, Object> encryptClientKey(@RequestBody EncryptClientKeyReq req) {
        if(StringUtils.isEmpty(req.getClientKey()) || StringUtils.isEmpty(req.getPublicKey())){
            throw new DataSecurityException("The public key and client key cannot be empty.");
        }
        SecretContext secretConfig = SpringUtil.getBean(SecretContext.class);
        PublicKey publicKeyObj = CryptoAsymmetricUtil.restorePublicKey(req.getPublicKey(),secretConfig.getRequestAsymmetricMode());
        String encrypted = CryptoAsymmetricUtil.encryptWithPublicKey(req.getClientKey(), publicKeyObj,secretConfig.getRequestAsymmetricMode());
        Map<String, Object> result = new HashMap<>();
        result.put("data", encrypted);
        return result;
    }

    // 获取客户端真实IP
    private String getClientIp(HttpServletRequest request) {
        // 常见的代理服务器转发客户端IP的HTTP头
        String[] headers = {
                "X-Forwarded-For",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_CLIENT_IP",
                "HTTP_X_FORWARDED_FOR"
        };

        // 优先从代理头中获取客户端IP
        for (String header : headers) {
            String ipList = request.getHeader(header);
            if (ipList != null && !ipList.isEmpty() && !"unknown".equalsIgnoreCase(ipList)) {
                // 可能有多个IP，第一个是客户端原始IP
                return ipList.split(",")[0];
            }
        }

        // 如果没有代理信息，直接获取连接的IP
        return request.getRemoteAddr();
    }
}    