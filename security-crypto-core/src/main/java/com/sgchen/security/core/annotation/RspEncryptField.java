package com.sgchen.security.core.annotation;

import java.lang.annotation.*;

/**
 * 返回实体类的字段上使用。对单个字段加密处理
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RspEncryptField {


}
