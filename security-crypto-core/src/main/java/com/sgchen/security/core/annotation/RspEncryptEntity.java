package com.sgchen.security.core.annotation;

import java.lang.annotation.*;

/**
 * 在字段实体上使用，指定需要加密的实体
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RspEncryptEntity {

}
