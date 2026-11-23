package com.sgchen.security.core.exception;


import cn.hutool.http.HttpStatus;

import java.io.Serializable;

public class AuthSecurityException extends RuntimeException implements Serializable {

    private static final long serialVersionUID = 1L;

    private int code = HttpStatus.HTTP_UNAUTHORIZED;

    private transient Object data;

    public AuthSecurityException() {
        super();
    }

    public AuthSecurityException(String message) {
        super(message);
    }

    public AuthSecurityException(String message, int code) {
        super(message);
        this.code = code;

    }

    public AuthSecurityException(String message, int code, Object data) {
        super(message);
        this.code = code;
        this.data = data;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public static String checkErrorMessage(String message) {
        if (message == null || message.isEmpty()) {
            return "系统异常，保存失败，请联系管理员！";
        } else {
            return message;
        }
    }
}
