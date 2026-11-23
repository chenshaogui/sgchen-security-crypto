package com.sgchen.security.transfer.rsa.bean;

import lombok.Data;

/**
 * 加密客户端key
 */
@Data
public class EncryptClientKeyReq {

    /**
     * 公钥内容
     */
    private String publicKey;

    /**
     * 客户端秘钥
     */
    private String clientKey;

}