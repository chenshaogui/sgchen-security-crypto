package com.sgchen.security.core.annotation;

import java.lang.annotation.*;

/**
 * 在mapper方法的字段上使用，指定需要加密的字段，需要和EncryptMethod注解一起使用才生效
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER})
public @interface EncryptParam {

    String value();
}
