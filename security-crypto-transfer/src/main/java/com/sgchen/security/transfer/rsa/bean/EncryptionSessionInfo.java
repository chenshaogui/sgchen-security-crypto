package com.sgchen.security.transfer.rsa.bean;

import lombok.Data;

import java.io.Serializable;

@Data
public class EncryptionSessionInfo implements Serializable {
    private String sessionId;
    private String clientKey;
    private String clientIp;
    private String publicKeyVersion;
    private Long createTime;
    private Long expireTime;
}
