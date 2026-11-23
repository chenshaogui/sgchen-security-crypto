package com.sgchen.security.core.annotation;

import java.lang.annotation.*;

@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface EncryptRequest {

    DesensitizedUnit[] value() default {};

    ReqDecryptField[] decryptField() default {};

}
