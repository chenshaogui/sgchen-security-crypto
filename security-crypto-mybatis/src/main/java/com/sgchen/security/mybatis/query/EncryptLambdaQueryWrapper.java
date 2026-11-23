package com.sgchen.security.mybatis.query;


import cn.hutool.extra.spring.SpringUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.LambdaUtils;
import com.baomidou.mybatisplus.core.toolkit.support.LambdaMeta;
import com.baomidou.mybatisplus.core.toolkit.support.SFunction;
import com.sgchen.security.core.annotation.EncryptField;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.util.CryptoSymmetricUtil;
import org.apache.ibatis.reflection.property.PropertyNamer;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;

/**
 * 加密数据查询
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
public class EncryptLambdaQueryWrapper<T> extends LambdaQueryWrapper<T> {

    @Override
    public LambdaQueryWrapper<T> eq(boolean condition, SFunction<T, ?> column, Object val) {
        SecretContext secretConfig = null;
        try {
            secretConfig = SpringUtil.getBean(SecretContext.class);
        } catch (Exception e) {
            return super.eq(condition, column, val);
        }
        if (condition && needEncrypt(column)) {
            val = CryptoSymmetricUtil.encrypt(val.toString(), secretConfig.getDbSecretKey(), secretConfig.getDbAlgorithm());
        }
        return super.eq(condition, column, val);
    }

    @Override
    public LambdaQueryWrapper<T> in(SFunction<T, ?> column, Collection<?> coll) {
        SecretContext secretConfig = null;
        try {
            secretConfig = SpringUtil.getBean(SecretContext.class);
        } catch (Exception e) {
            return super.in(column, coll);
        }
        if (needEncrypt(column)) {
            Collection<String> newColl = new ArrayList<>();
            for (Object val : coll) {
                newColl.add(CryptoSymmetricUtil.encrypt(val.toString(), secretConfig.getDbSecretKey(), secretConfig.getDbAlgorithm()));
            }
            return super.in(column, newColl);
        }
        return super.in(column, coll);
    }

    @Override
    public LambdaQueryWrapper<T> notIn(SFunction<T, ?> column, Collection<?> coll) {
        SecretContext secretConfig = null;
        try {
            secretConfig = SpringUtil.getBean(SecretContext.class);
        } catch (Exception e) {
            return super.notIn(column, coll);
        }
        if (needEncrypt(column)) {
            Collection<String> newColl = new ArrayList<>();
            for (Object val : coll) {
                newColl.add(CryptoSymmetricUtil.encrypt(val.toString(), secretConfig.getDbSecretKey(), secretConfig.getDbAlgorithm()));
            }
            return super.notIn(column, newColl);
        }
        return super.notIn(column, coll);
    }

    private boolean needEncrypt(SFunction<T, ?> column) {
        try {
            LambdaMeta lambda = LambdaUtils.extract(column);
            Class<?> entityClass = lambda.getInstantiatedClass(); // 获取实体类
            String fieldName = PropertyNamer.methodToProperty(lambda.getImplMethodName());
            Field field = entityClass.getDeclaredField(fieldName);
            return field.isAnnotationPresent(EncryptField.class);
        } catch (Exception e) {
            return false;
        }
    }
}
