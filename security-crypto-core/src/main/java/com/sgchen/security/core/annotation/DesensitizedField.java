package com.sgchen.security.core.annotation;


import com.sgchen.security.core.enums.DesensitizedMode;

import java.lang.annotation.*;

/**
 * 在实体类上使用，指定需要脱敏的字段
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface DesensitizedField {


    DesensitizedMode mode() default DesensitizedMode.defaultMode;

    int front() default 0;

    int tail() default 0;

}
