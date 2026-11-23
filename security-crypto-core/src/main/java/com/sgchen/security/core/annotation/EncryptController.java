package com.sgchen.security.core.annotation;

import java.lang.annotation.*;

@Inherited
@Documented
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface EncryptController {

    DesensitizedUnit[] value() default {};

    ReqDecryptField[] decryptField() default {};

}
