package com.sgchen.security.core.enums;

import lombok.Getter;

@Getter
public enum RequestSolveMode {

    /**
     * 全参数加密模式
     */
    FULL,

    /**
     * 单个字段加解密
     */
    FIELD;

}