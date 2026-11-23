package com.sgchen.security.transfer.util;

import com.sgchen.security.core.annotation.EncryptController;
import com.sgchen.security.core.annotation.EncryptRequest;
import com.sgchen.security.core.annotation.ReqDecryptField;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;


/**
 * 签名
 *
 * @author sgchen
 */
public class RequestFilterUtil {

    private RequestFilterUtil() {
    }

    /**
     * 判断是否需要加解密
     *
     * @param handler
     * @return
     */
    public static boolean hasDecryptAnnotation(HandlerExecutionChain handler) {
        if (handler == null) {
            return false;
        }
        if (handler.getHandler() instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler.getHandler();
            return handlerMethod.getMethodAnnotation(EncryptRequest.class) != null || handlerMethod.getBeanType().isAnnotationPresent(EncryptController.class);
        }
        return false;
    }

    public static ReqDecryptField[] getDecryptAnnotation(HandlerExecutionChain handler) {
        if (handler == null) {
            return null;
        }
        if (handler.getHandler() instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler.getHandler();
            if(handlerMethod.hasMethodAnnotation(EncryptRequest.class)){
                EncryptRequest methodAnnotation = handlerMethod.getMethodAnnotation(EncryptRequest.class);
                if(methodAnnotation!=null && methodAnnotation.decryptField()!=null){
                   return methodAnnotation.decryptField();
                }
            }
            if(handlerMethod.getBeanType().isAnnotationPresent(EncryptController.class)){
                EncryptController annotation = handlerMethod.getBeanType().getAnnotation(EncryptController.class);
                if(annotation!=null && annotation.decryptField()!=null){
                    return annotation.decryptField();
                }
            }
        }
        return null;
    }

}
