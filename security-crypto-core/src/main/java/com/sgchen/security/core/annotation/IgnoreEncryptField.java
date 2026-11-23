package com.sgchen.security.core.annotation;

import java.lang.annotation.*;

/**
 * 在实体类的字段上使用，指定需要加密的字段，当实体上有EncryptEntity注解，并且autoMark标记为true时才生效
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface IgnoreEncryptField {
}
