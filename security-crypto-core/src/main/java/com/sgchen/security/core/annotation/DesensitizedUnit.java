package com.sgchen.security.core.annotation;


import com.sgchen.security.core.enums.DesensitizedMode;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({})
public @interface DesensitizedUnit {

    String field();

    DesensitizedMode mode() default DesensitizedMode.defaultMode;

    int front() default 0;

    int tail() default 0;

}
