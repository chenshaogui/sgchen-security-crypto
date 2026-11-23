package com.sgchen.security.mybatis.handler;


import cn.hutool.extra.spring.SpringUtil;
import com.alibaba.fastjson2.JSONObject;
import com.baomidou.mybatisplus.annotation.TableField;
import com.sgchen.security.core.annotation.EncryptEntity;
import com.sgchen.security.core.annotation.EncryptField;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.util.CryptoSymmetricUtil;
import com.sgchen.security.core.util.FieldNameConverter;
import com.sgchen.security.core.util.ReflectionUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collection;

@Component
@Slf4j
@ConditionalOnProperty(
        prefix = "csg-security.database",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class CryptoTableHandler {

    /**
     * 获取EntityTableMappingHandler bean
     * @return EntityTableMappingHandler
     */
    public EntityTableMappingHandler getEntityTableMappingHandler(){
        EntityTableMappingHandler entityTableMappingHandler = null;
        try {
            entityTableMappingHandler = SpringUtil.getBean(EntityTableMappingHandler.class);
            return entityTableMappingHandler;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
           throw new SecurityException("获取【EntityTableMappingHandler】实例bean异常，请检查是否开启datasource");
        }
    }

    /**
     * 根据表的数据加密
     *
     * @param tableName 表名
     * @param data      加密的数据
     * @return obj
     */
    public Object getEncryptTableData(String tableName, Object data) {
        if (data == null) {
            return null;
        }
        Class<?> entityClass = getEntityTableMappingHandler().getEntityClassByTableName(tableName);
        if (entityClass == null) {
            return data;
        }
        if (ReflectionUtils.isPlainObject(data)) {
            processEncrypt(entityClass, data);
        }
        if (data instanceof Collection) {
            Collection<?> objArr = (Collection) data;
            for (Object obj : objArr) {
                processEncrypt(entityClass, obj);
            }
        }
        return data;
    }


    /**
     * 根据表的数据加密
     *
     * @param tableName  表名
     * @param data       加密的数据
     * @param caseFormat 字段key格式转换
     * @return obj
     */
    public Object getEncryptTableData(String tableName, Object data, FieldNameConverter.CaseFormat caseFormat) {
        if (data == null) {
            return null;
        }
        Class<?> entityClass = getEntityTableMappingHandler().getEntityClassByTableName(tableName);
        if (entityClass == null) {
            return data;
        }
        if (ReflectionUtils.isPlainObject(data)) {
            processEncrypt(entityClass, data, caseFormat);
        }
        if (data instanceof Collection) {
            Collection<?> objArr = (Collection) data;
            for (Object obj : objArr) {
                processEncrypt(entityClass, obj, caseFormat);
            }
        }
        return data;
    }

    /**
     * 根据表的数据加密【无返回值】
     *
     * @param tableName 表名
     * @param data      加密的数据
     */
    public void processEncryptTable(String tableName, Object data) {
        getEncryptTableData(tableName, data);
    }

    /**
     * 根据表的数据解密
     *
     * @param tableName 表名
     * @param data      加密的数据
     * @return obj
     */
    public Object getDecryptTableData(String tableName, Object data) {
        if (data == null) {
            return null;
        }
        Class<?> entityClass = getEntityTableMappingHandler().getEntityClassByTableName(tableName);
        if (entityClass == null) {
            return data;
        }
        if (ReflectionUtils.isPlainObject(data)) {
            processDecrypt(entityClass, data);
        }
        if (data instanceof Collection) {
            Collection<?> objArr = (Collection) data;
            for (Object obj : objArr) {
                processDecrypt(entityClass, obj);
            }
        }
        return data;
    }

    /**
     * 根据表的数据解密
     *
     * @param tableName  表名
     * @param data       加密的数据
     * @param caseFormat 字段key格式转换
     * @return obj
     */
    public Object getDecryptTableData(String tableName, Object data, FieldNameConverter.CaseFormat caseFormat) {
        if (data == null) {
            return null;
        }
        Class<?> entityClass = getEntityTableMappingHandler().getEntityClassByTableName(tableName);
        if (entityClass == null) {
            return data;
        }
        if (ReflectionUtils.isPlainObject(data)) {
            processDecrypt(entityClass, data, caseFormat);
        }
        if (data instanceof Collection) {
            Collection<?> objArr = (Collection) data;
            for (Object obj : objArr) {
                processDecrypt(entityClass, obj, caseFormat);
            }
        }
        return data;
    }

    /**
     * 根据表的数据解密【无返回值】
     *
     * @param tableName 表名
     * @param data      加密的数据
     */
    public void processDecryptTable(String tableName, Object data) {
        getDecryptTableData(tableName, data);
    }

    /**
     * 根据对象注解对对象加解密
     *
     * @param entityClass 表对应的对象
     * @param data        加解密数据
     * @return obj
     */
    public Object processEncrypt(Class<?> entityClass, Object data) {
        if (data == null) {
            return null;
        }
        return processEncrypt(entityClass, data, FieldNameConverter.CaseFormat.UNDERSCORE_TO_CAMEL);
    }

    /**
     * 根据对象注解对对象加解密
     *
     * @param entityClass 表对应的对象
     * @param data        加解密数据
     * @param caseFormat  字段值格式转换
     * @return obj
     */
    public Object processEncrypt(Class<?> entityClass, Object data, FieldNameConverter.CaseFormat caseFormat) {
        if (data == null) {
            return null;
        }
        boolean needEncryptEntity = entityClass.isAnnotationPresent(EncryptEntity.class);
        //不需要加密，直接返回
        if (!needEncryptEntity) {
            return data;
        }
        SecretContext secretConfig = null;
        try {
            secretConfig = SpringUtil.getBean(SecretContext.class);
        } catch (Exception e) {
            log.warn("秘钥未配置，参数加密放行");
            return data;
        }
        SecretContext finalSecretConfig = secretConfig;
        if (data instanceof JSONObject) {
            JSONObject dataTrans = (JSONObject) data;
            Arrays.stream(entityClass.getDeclaredFields())
                    .filter(f -> f.isAnnotationPresent(EncryptField.class))
                    .forEach(f -> {
                        String fieldName = getColumnName(f, caseFormat);
                        if (dataTrans.containsKey(fieldName)) {
                            String cryptStr = CryptoSymmetricUtil.encrypt(dataTrans.getString(fieldName), finalSecretConfig.getDbSecretKey(), finalSecretConfig.getDbAlgorithm());
                            dataTrans.put(fieldName, cryptStr);
                        }
                    });
        } else {
            try {
                SecretHandler.encryptByEntity(data, secretConfig);
            } catch (IllegalAccessException e) {
                log.error("对象加密失败");
            }
        }
        return data;
    }

    /**
     * 根据对象注解对对象加解密
     *
     * @param entityClass 表对应的对象
     * @param data        加解密数据
     * @return obj
     */
    public Object processDecrypt(Class<?> entityClass, Object data) {
        if (data == null) {
            return null;
        }
        return processDecrypt(entityClass, data, FieldNameConverter.CaseFormat.UNDERSCORE_TO_CAMEL);
    }

    /**
     * 根据对象注解对对象加解密
     *
     * @param entityClass 表对应的对象
     * @param data        加解密数据
     * @param caseFormat  字段值格式转换
     * @return obj
     */
    public Object processDecrypt(Class<?> entityClass, Object data, FieldNameConverter.CaseFormat caseFormat) {
        if (data == null) {
            return null;
        }
        boolean needEncryptEntity = entityClass.isAnnotationPresent(EncryptEntity.class);
        //不需要加密，直接返回
        if (!needEncryptEntity) {
            return data;
        }
        SecretContext secretConfig = null;
        try {
            secretConfig = SpringUtil.getBean(SecretContext.class);
        } catch (Exception e) {
            log.warn("秘钥未配置，参数解密放行");
            return data;
        }
        SecretContext finalSecretConfig = secretConfig;
        if (data instanceof JSONObject) {
            JSONObject dataTrans = (JSONObject) data;
            Arrays.stream(entityClass.getDeclaredFields())
                    .filter(f -> f.isAnnotationPresent(EncryptField.class))
                    .forEach(f -> {
                        String fieldName = getColumnName(f, caseFormat);
                        if (dataTrans.containsKey(fieldName)) {
                            String cryptStr = CryptoSymmetricUtil.decrypt(dataTrans.getString(fieldName), finalSecretConfig.getDbSecretKey(), finalSecretConfig.getDbAlgorithm());
                            dataTrans.put(fieldName, cryptStr);
                        }
                    });
        } else {
            try {
                SecretHandler.doDecrypt(data, secretConfig);
            } catch (IllegalAccessException e) {
                log.error("对象解密失败");
            }
        }
        return data;
    }

    /**
     * 获取加密的字段名
     *
     * @param field      字段名
     * @param caseFormat 转换格式
     * @return str
     */
    public String getColumnName(Field field, FieldNameConverter.CaseFormat caseFormat) {
        // 优先获取注解定义的字段名
        if (field.isAnnotationPresent(TableField.class)) {
            String annotatedName = field.getAnnotation(TableField.class).value();
            if (StringUtils.isNotBlank(annotatedName)) {
                // 字段注解的值转为驼峰格式
                return FieldNameConverter.convert(annotatedName, caseFormat);
            }
        }

        // 默认返回字段名（可添加驼峰转下划线逻辑）
        return field.getName();
    }

}
