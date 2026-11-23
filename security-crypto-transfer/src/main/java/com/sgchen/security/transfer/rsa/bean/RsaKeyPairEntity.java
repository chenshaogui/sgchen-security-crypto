package com.sgchen.security.transfer.rsa.bean;

import lombok.Data;

/**
 * 密钥对实体类，不能通过接口泄露
 */
@Data
public class RsaKeyPairEntity {

    /**
     * 公钥版本号（如UUID）
     */
    private String version;
    /**
     * 公钥内容（Base64）
     */
    private String publicKey;

    /**
     * 私钥内容（Base64）
     */
    private String privateKey;

    /**
     * 过期时间戳（毫秒）
     */
    private Long expireTime;

}