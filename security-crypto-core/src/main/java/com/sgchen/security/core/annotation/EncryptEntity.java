package com.sgchen.security.core.annotation;

import java.lang.annotation.*;

/**
 * 在实体类上使用，指定需要加密的实体
 */
@Inherited
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptEntity {


    boolean autoMark() default false;

}
