package com.sgchen.security.core.enums;

import lombok.Getter;

@Getter
public enum RequestKeyTransMode {

    /**
     * 非对称加密混合，秘钥会话模式
     */
    SESSION,

    /**
     * 非对称加密混合，请求头秘钥模式
     */
    HEADER;

}