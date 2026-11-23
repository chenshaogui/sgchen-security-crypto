package com.sgchen.security.mybatis.interceptor;


import cn.hutool.extra.spring.SpringUtil;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.exception.DataSecurityException;
import com.sgchen.security.mybatis.handler.SecretHandler;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.executor.resultset.ResultSetHandler;
import org.apache.ibatis.plugin.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * mybatis 结果解密拦截器
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
@Intercepts({
        @Signature(type = ResultSetHandler.class, method = "handleResultSets", args = {Statement.class}),
})
@Slf4j
@Component
@ConditionalOnProperty(
        prefix = "csg-security.database",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class MybatisResultSetDecryptInterceptor implements Interceptor {

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        Object resultObject = invocation.proceed();
        SecretContext secretConfig = null;
        try {
            secretConfig = SpringUtil.getBean(SecretContext.class);
        } catch (Exception e) {
            log.warn("秘钥未配置，结果解密放行");
            return resultObject;
        }
        try {
            if (Objects.isNull(resultObject)) {
                return null;
            }
            // 解密列表数据
            decryptResultData(resultObject, secretConfig);

            return resultObject;
        } catch (Exception e) {
            log.error("字段解密失败！", e);
            throw new DataSecurityException("字段解密失败！");
        }

    }

    /**
     * 递归解密数据
     * @param resultObject 返回结果
     * @param secretConfig 加解密配置信息
     * @throws IllegalAccessException e
     */
    private static void decryptResultData(Object resultObject, SecretContext secretConfig) throws IllegalAccessException {
        if (resultObject instanceof ArrayList) {
            @SuppressWarnings("rawtypes")
            List list = (ArrayList) resultObject;
            if (!CollectionUtils.isEmpty(list)) {
                for (Object result : list) {
                    decryptResultData(result, secretConfig);
                }
            }
        } else {
            // 解密
            SecretHandler.doDecrypt(resultObject, secretConfig);
        }
    }

    @Override
    public Object plugin(Object o) {
        return Plugin.wrap(o, this);
    }

}
