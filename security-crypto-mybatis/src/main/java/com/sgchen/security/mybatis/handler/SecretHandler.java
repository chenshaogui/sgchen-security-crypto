package com.sgchen.security.mybatis.handler;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.sgchen.security.core.annotation.EncryptEntity;
import com.sgchen.security.core.annotation.EncryptField;
import com.sgchen.security.core.annotation.EncryptParam;
import com.sgchen.security.core.annotation.IgnoreEncryptField;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.exception.DataSecurityException;
import com.sgchen.security.core.util.CryptoSymmetricUtil;
import com.sgchen.security.core.util.FieldNameConverter;
import com.sgchen.security.core.util.ReflectionUtils;
import org.apache.ibatis.binding.MapperMethod;

import java.lang.reflect.*;
import java.util.*;

/**
 * 加密处理类，主要负责对加密注解的判断
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
public class SecretHandler {

    private SecretHandler() {
    }

    /**
     * 对数据加密，适用于数据insert、update语句
     * 场景一、调用Wrapper中的自带的api接口
     * 场景二、调用Mapper文件中的方法接口，当参数是对象时
     * 场景三、调用Mapper文件中的方法接口，当参数是单个参数时
     *
     * @param paramEntity 参数实体
     * @throws IllegalAccessException e
     */
    public static void doEncrypt(String methodPath, Object paramEntity, SecretContext secretConfig) throws IllegalAccessException, ClassNotFoundException {
        if (paramEntity == null) {
            return;
        }
        // 处理方法上面的参数注解 EncryptParam
        Class<?> paramEntityClass = paramEntity.getClass();
        if (paramEntityClass.equals(MapperMethod.ParamMap.class)) {
            //如果当前是加密并且方法入参不是实体类，那么看是方法上是否有加密参数注解
            //获取类和方法名段断点索引
            int lastIndexOf = methodPath.lastIndexOf(".");
            //获取执行的类路径
            Class<?> methodClass = Class.forName(methodPath.substring(0, lastIndexOf));
            //执行的获取方法名
            String methodName = methodPath.substring(lastIndexOf + 1);
            //获取所有执行的方法，找到当前执行的方法
            Method[] declaredMethods = methodClass.getDeclaredMethods();
            //定义当前执行的加密方法
            Method currentEncryptMethod = null;
            //循环所有方法，找到当前执行的加密方法
            for (Method declaredMethod : declaredMethods) {
                //如果当前执行的方法带有加密注解，则获取执行的参数
                if (methodName.equals(declaredMethod.getName())) {
                    //找到了当前需要加密的方法，跳出循环
                    currentEncryptMethod = declaredMethod;
                    break;
                }
            }
            if (currentEncryptMethod != null) {
                //获取所有参数
                Parameter[] parameters = currentEncryptMethod.getParameters();
                //遍历该方法的所有参数
                for (Parameter parameter : parameters) {
                    //对带有加密参数注解的参数进行加密处理
                    if (parameter.isAnnotationPresent(EncryptParam.class)) {
                        //noinspection rawtypes
                        dealMapperXmlEncryptParam((MapperMethod.ParamMap) paramEntity, secretConfig, parameter);
                    }
                }
            }
        }

        // 处理实体类的加密注解 EncryptEntity
        Set<Object> objectList = new HashSet<>();
        if (paramEntity instanceof Map<?, ?>) {
            Collection<?> values = ((Map<?, ?>) paramEntity).values();
            objectList.addAll(values);
        } else {
            objectList.add(paramEntity);
        }
        for (Object entity : objectList) {
            //如果查询参数是实体，则进行对实体进行判定并加密
            encryptByEntity(entity, secretConfig);
        }

    }

    /**
     * 获取 BaseMapper<T> 中实体类的表名
     * @param mapperInterface BaseMapper子类
     * @return str
     */
    private String getMapperTableName(Class<?> mapperInterface){
        // 获取实体类型
        Class<?> entityClass = null;
        // 检查是否继承BaseMapper
        if (BaseMapper.class.isAssignableFrom(mapperInterface)) {
            // 获取泛型类型
            Type[] genericInterfaces = mapperInterface.getGenericInterfaces();
            for (Type genericInterface : genericInterfaces) {
                if (genericInterface instanceof ParameterizedType) {
                    ParameterizedType parameterizedType = (ParameterizedType) genericInterface;
                    if (parameterizedType.getRawType() == BaseMapper.class) {
                        entityClass = (Class<?>) parameterizedType.getActualTypeArguments()[0];
                        break;
                    }
                }
            }
        }
        // 通过实体类获取表名
        String tableName = null;
        if (entityClass != null) {
            TableName tableAnnotation = entityClass.getAnnotation(TableName.class);
            tableName = tableAnnotation != null ?
                    tableAnnotation.value() :
                    FieldNameConverter.convert(entityClass.getSimpleName(), FieldNameConverter.CaseFormat.CAMEL_TO_UNDERSCORE);
        }
        return tableName;
    }

    /**
     * 处理 @EncryptParam 参数解密注解
     * @param paramEntity 参数实体class
     * @param secretConfig 解密信息
     * @param parameter 参数信息
     * @throws IllegalAccessException e
     */
    @SuppressWarnings("rawtypes")
    private static void dealMapperXmlEncryptParam(MapperMethod.ParamMap paramEntity, SecretContext secretConfig, Parameter parameter) throws IllegalAccessException {
        //定义加密查询的变量名
        String paramName;
        //定义原始参数值
        Object paramValue;
        //获取参数类型
        Class<?> parameterType = parameter.getType();
        //通过注解获取参数值
        EncryptParam encryptParam = parameter.getAnnotation(EncryptParam.class);
        //获取加密的参数名，要和mybatis的xml使用的sql一致
        String encryptParamName = encryptParam.value();
        //如果没有设置的话，尝试取默认参数名（args0、args1、args2...）
        if (StrUtil.isBlank(encryptParamName)) {
            //获取加密查询的变量名
            paramName = parameter.getName();
            //获取原始值
            paramValue = paramEntity.get(parameter.getName());
        } else {
            //如果传入的参数实体包含注解设置的名称，则可以获取传入的值
            if (paramEntity.containsKey(encryptParamName)) {
                //获取加密查询的变量名
                paramName = encryptParamName;
                //获取原始值
                paramValue = paramEntity.get(encryptParamName);
            } else {
                //如果不包含就抛异常
                throw new DataSecurityException("EncryptParam注解设置的参数名【" + encryptParamName + "】不在mybatis查询的参数当中，请检查！");
            }
        }
        //原始值为空直接跳过
        if (paramValue == null) {
            return;
        }
        //如果是字符串，则直接对字符串的值进行加密
        if (String.class.equals(parameterType)) {
            //原始值判空
            if (StrUtil.isNotBlank(paramValue.toString())) {
                //对值加密
                // noinspection unchecked
                paramEntity.put(paramName, CryptoSymmetricUtil.encrypt(paramValue.toString(), secretConfig.getDbSecretKey(), secretConfig.getDbAlgorithm()));
            }
        } else if (List.class.equals(parameterType)) {
            //如果是集合，则遍历集合，看实体类的参数是否有加密注解
            //noinspection rawtypes
            for (Object object : (List) paramValue) {
                if (object != null) {
                    //对实体类加密处理
                    encryptByEntity(object, secretConfig);
                }
            }
        }
    }

    /**
     * 对数据加/解密
     *
     * @param paramEntity 参数实体
     * @throws IllegalAccessException e
     */
    public static void doDecrypt(Object paramEntity, SecretContext secretConfig) throws IllegalAccessException {
        if (paramEntity == null) {
            return;
        }
        //获取参数类的class
        decryptByEntity(paramEntity, secretConfig);
    }


    /**
     * 实体类加密处理
     *
     * @param paramEntity 加密实体类
     * @throws IllegalAccessException e
     */
    public static void encryptByEntity(Object paramEntity, SecretContext secretConfig) throws IllegalAccessException {
        if (paramEntity == null) {
            return;
        }
        //获取实体类的class对象
        Class<?> paramEntityClass = paramEntity.getClass();
        //如果是实体类，判断该实体类是否添加EncryptEntity注解，如果没有EncryptEntity注解，则不需要加密操作
        boolean needEncryptEntity = paramEntityClass.isAnnotationPresent(EncryptEntity.class);
        //不需要加密，直接返回
        if (!needEncryptEntity) {
            return;
        }
        //是否自动标记字段
        boolean autoMark = paramEntityClass.getAnnotation(EncryptEntity.class).autoMark();
        //获取实体类的所有字段值
        List<Field> declaredFields = ReflectionUtils.getAllFields(paramEntityClass);
        //遍历字段加密，如果自动标记为true则除了忽略的所有字段全部需要加密
        if (autoMark) {
            for (Field declaredField : declaredFields) {
                //判断字段类型是否是字符串，不是字符串直接跳过
                Class<?> fieldType = declaredField.getType();
                if (!String.class.equals(fieldType)) {
                    continue;
                }
                //判断字段是否有忽略加密注解
                boolean ignoreEncrypt = declaredField.isAnnotationPresent(IgnoreEncryptField.class);
                if (ignoreEncrypt) {
                    continue;
                }
                encryptField(paramEntity, secretConfig, declaredField);
            }
        } else {
            //否则只对带有EncryptField字段的字段加密
            for (Field declaredField : declaredFields) {
                //判断字段类型是否是字符串，不是字符串直接跳过
                Class<?> fieldType = declaredField.getType();
                if (!String.class.equals(fieldType)) {
                    continue;
                }
                //判断是否有加密注解
                boolean needEncryptField = declaredField.isAnnotationPresent(EncryptField.class);
                if (!needEncryptField) {
                    continue;
                }
                encryptField(paramEntity, secretConfig, declaredField);
            }
        }
    }

    /**
     * 实体类解密处理
     *
     * @param paramEntity 加密实体类
     * @throws IllegalAccessException e
     */
    private static void decryptByEntity(Object paramEntity, SecretContext secretConfig) throws IllegalAccessException {
        if (paramEntity == null) {
            return;
        }
        //获取实体类的class对象
        Class<?> paramEntityClass = paramEntity.getClass();
        //如果是实体类，判断该实体类是否添加EncryptEntity注解，如果没有EncryptEntity注解，则不需要加密操作
        boolean needEncryptEntity = paramEntityClass.isAnnotationPresent(EncryptEntity.class);
        //不需要加密，直接返回
        if (!needEncryptEntity) {
            return;
        }
        //是否自动标记字段
        boolean autoMark = paramEntityClass.getAnnotation(EncryptEntity.class).autoMark();
        //获取实体类的所有字段值
        List<Field> declaredFields = ReflectionUtils.getAllFields(paramEntityClass);
        //遍历字段加密，如果自动标记为true则除了忽略的所有字段全部需要加密
        if (autoMark) {
            for (Field declaredField : declaredFields) {
                //判断字段类型是否是字符串，不是字符串直接跳过
                Class<?> fieldType = declaredField.getType();
                if (!String.class.equals(fieldType)) {
                    continue;
                }
                //判断字段是否有忽略加密注解
                boolean ignoreEncrypt = declaredField.isAnnotationPresent(IgnoreEncryptField.class);
                if (ignoreEncrypt) {
                    continue;
                }
                decryptField(paramEntity, secretConfig, declaredField);
            }
        } else {
            //否则只对带有EncryptField字段的字段加密
            for (Field declaredField : declaredFields) {
                //判断字段类型是否是字符串，不是字符串直接跳过
                Class<?> fieldType = declaredField.getType();
                if (!String.class.equals(fieldType)) {
                    continue;
                }
                //判断是否有加密注解
                boolean needEncryptField = declaredField.isAnnotationPresent(EncryptField.class);
                if (!needEncryptField) {
                    continue;
                }
                decryptField(paramEntity, secretConfig, declaredField);
            }
        }
    }

    /**
     * 加密字段
     *
     * @param paramEntity   参数实体
     * @param declaredField 待处理字段
     * @throws IllegalAccessException e
     */
    private static void encryptField(Object paramEntity, SecretContext secretConfig, Field declaredField) throws IllegalAccessException {
        if (paramEntity == null) {
            return;
        }
        //如果自动标记字段则除了忽略的所有字段全部需要加密
        declaredField.setAccessible(true);
        //获取原始值
        Object paramValue = declaredField.get(paramEntity);
        //加解密操作
        if (paramValue != null && StrUtil.isNotBlank(paramValue.toString())) {
            //设置加密值
            declaredField.set(paramEntity, CryptoSymmetricUtil.encrypt(paramValue.toString(), secretConfig.getDbSecretKey(), secretConfig.getDbAlgorithm()));
            declaredField.setAccessible(false);
        }
    }

    /**
     * 解密字段
     *
     * @param paramEntity   参数实体
     * @param declaredField 待处理字段
     * @throws IllegalAccessException e
     */
    private static void decryptField(Object paramEntity, SecretContext secretConfig, Field declaredField) throws IllegalAccessException {
        if (paramEntity == null) {
            return;
        }
        //如果自动标记字段则除了忽略的所有字段全部需要加密
        declaredField.setAccessible(true);
        //获取原始值
        Object paramValue = declaredField.get(paramEntity);
        //加解密操作
        if (paramValue != null && StrUtil.isNotBlank(paramValue.toString())) {
            //设置解密值
            try {
                declaredField.set(paramEntity, CryptoSymmetricUtil.decrypt(paramValue.toString(), secretConfig.getDbSecretKey(), secretConfig.getDbAlgorithm()));
            } catch (Exception e) {
                throw new DataSecurityException("解密失败，异常信息为【" + e.getMessage() + "】，请联系管理员");
            }
            declaredField.setAccessible(false);
        }
    }

}
