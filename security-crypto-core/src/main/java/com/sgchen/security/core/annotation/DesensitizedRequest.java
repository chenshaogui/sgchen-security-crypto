package com.sgchen.security.core.annotation;

import java.lang.annotation.*;

@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface DesensitizedRequest {

    DesensitizedUnit[] value() default {};

}
