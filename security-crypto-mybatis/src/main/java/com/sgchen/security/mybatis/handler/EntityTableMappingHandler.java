package com.sgchen.security.mybatis.handler;

import cn.hutool.extra.spring.SpringUtil;
import com.baomidou.mybatisplus.annotation.TableName;
import com.sgchen.security.core.annotation.EncryptEntity;
import com.sgchen.security.core.annotation.EncryptField;
import com.sgchen.security.core.util.FieldNameConverter;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.session.Configuration;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.util.*;
import java.util.function.Predicate;

/**
 * 存储表名与实体类之间的关系数据
 *
 * @author sgchen
 * @date 2025/6/21 9:05
 */
@Component
@ConditionalOnProperty(
        prefix = "csg-security.database",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class EntityTableMappingHandler {

    // 缓存表名与实体类的映射关系
    private Map<String, Class<?>> tableEntityMap = new HashMap<>();

    private Map<Class<?>, String> entityTableMap = new HashMap<>();

    private Map<String, List<String>> tableWithSecretColumnMap = new HashMap<>();

    public Map<String, Class<?>> getTableEntityMap() {
        if (tableEntityMap.isEmpty()) {
            initMapping();
        }
        return tableEntityMap;
    }

    public Map<Class<?>, String> getEntityTableMap() {
        if (entityTableMap.isEmpty()) {
            initMapping();
        }
        return entityTableMap;
    }

    /**
     * 获取表的加密字段
     * @param tableName 表名
     * @return list
     */
    public List<String> getSecretColumnByTableName(String tableName) {
        // tableWithSecretColumnMap 可能为空，使用entityTableMap判断
        if (entityTableMap.isEmpty()) {
            initMapping();
        }
        return tableWithSecretColumnMap.get(tableName);
    }

    /**
     * 初始化映射关系
     * 表名默认转为下划线模式
     */
    public void initMapping() {
        SqlSessionTemplate template = SpringUtil.getBean(SqlSessionTemplate.class);
        Configuration configuration = template.getConfiguration();
        // 获取所有已注册的Mapper
        Collection<Class<?>> mapperClasses = configuration.getMapperRegistry().getMappers();

        Predicate<Class<?>> isEntity = clazz ->
                !clazz.isPrimitive() &&
                        !clazz.isArray() &&
                        !Map.class.isAssignableFrom(clazz) &&
                        !Number.class.isAssignableFrom(clazz) &&
                        !clazz.getName().startsWith("java.");

        // 遍历Mapper获取实体类与表映射
        for (Class<?> mapperClass : mapperClasses) {
            String namespace = mapperClass.getName();
            Collection<String> mappedStatementNames = configuration.getMappedStatementNames();
            mappedStatementNames.stream()
                    .filter(name -> name.startsWith(namespace))
                    .forEach(name -> {
                        MappedStatement ms = configuration.getMappedStatement(name);
                        if (ms.getResultMaps() != null) {
                            ms.getResultMaps().stream()
                                    .filter(rm -> isEntity.test(rm.getType()))
                                    .forEach(rm -> {
                                        Class<?> type = rm.getType();
                                        if (type != null) {
                                            TableName tableAnnotation = rm.getType().getAnnotation(TableName.class);
                                            String tableName = tableAnnotation != null ?
                                                    tableAnnotation.value() :
                                                    FieldNameConverter.convert(type.getSimpleName(), FieldNameConverter.CaseFormat.CAMEL_TO_UNDERSCORE);
                                            this.entityTableMap.put(type, tableName);
                                            this.tableEntityMap.put(tableName, type);
                                            List<String> encryptedFields = getEncryptedFields(type);
                                            if (!encryptedFields.isEmpty()) {
                                                this.tableWithSecretColumnMap.put(tableName, encryptedFields);
                                            }
                                        }
                                    });
                        }
                    });
        }
    }

    /**
     * 获取类上的加密字段
     * @param entity 实体类
     * @return list
     */
    public static List<String> getEncryptedFields(Object entity) {
        List<String> encryptedFields = new ArrayList<>();
        if (entity == null) return encryptedFields;

        Class<?> clazz = entity.getClass();
        // 检查类是否标记了@EncryptEntity
        if (clazz.isAnnotationPresent(EncryptEntity.class)) {
            // 获取所有声明的字段（包括私有字段）
            Field[] fields = clazz.getDeclaredFields();
            for (Field field : fields) {
                // 检查字段是否标记了@EncryptField
                if (field.isAnnotationPresent(EncryptField.class)) {
                    encryptedFields.add(field.getName());
                }
            }
        }
        return encryptedFields;
    }

    // 根据表名获取实体类
    public Class<?> getEntityClassByTableName(String tableName) {
        if (tableEntityMap.isEmpty()) {
            initMapping();
        }
        return tableEntityMap.get(tableName);
    }

    // 根据实体类获取表名
    public String getTableNameByEntity(Class<?> entityClass) {
        if (entityTableMap.isEmpty()) {
            initMapping();
        }
        return entityTableMap.get(entityClass);
    }
}
