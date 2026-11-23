package com.sgchen.security.mybatis.interceptor;


import cn.hutool.extra.spring.SpringUtil;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.exception.DataSecurityException;
import com.sgchen.security.mybatis.handler.SecretHandler;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.executor.parameter.ParameterHandler;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.sql.PreparedStatement;

/**
 * mybatis 参数加密拦截器
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
@Slf4j
@Component
@Intercepts({
        @Signature(type = ParameterHandler.class, method = "setParameters", args = {PreparedStatement.class})
})
@ConditionalOnProperty(
        prefix = "csg-security.database",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class MybatisParameterEncryptInterceptor implements Interceptor {


    @Override
    public Object intercept(Invocation invocation) {
        try {
            SecretContext secretConfig = null;
            try {
                secretConfig = SpringUtil.getBean(SecretContext.class);
            } catch (Exception e) {
                log.warn("秘钥未配置，参数加密放行");
                return invocation.proceed();
            }
            ParameterHandler parameterHandler = (ParameterHandler) invocation.getTarget();
            Field mappedStateField = parameterHandler.getClass().getDeclaredField("mappedStatement");
            mappedStateField.setAccessible(true);
            MappedStatement mappedStatement = (MappedStatement) mappedStateField.get(parameterHandler);
            //安全处理
            SecretHandler.doEncrypt(mappedStatement.getId(), parameterHandler.getParameterObject(), secretConfig);
            return invocation.proceed();
        } catch (Exception e) {
            log.error("字段加密失败！", e);
            throw new DataSecurityException("字段加密失败！");
        }
    }

    /**
     * 默认配置，否则当前拦截器不会加入拦截器链
     */
    @Override
    public Object plugin(Object o) {
        return Plugin.wrap(o, this);
    }

}

