# 数据存储加解密

基于SpringBoot和Mybatis的数据安全处理，在数据持久层对数据进行加/解密。

1、通过注解在保存数据的时候将指定字段进行加密处理，查询时自动解密\
2、通过注解在查询数据的时候对指定字段进行脱敏处理\


SpringBoot+MyBatis-Plus ，HuTool的工具包、Lombok插件以及Bouncy Castle加密包、fastjson2工具

数据存储加解密使用手册

# 一、SpringBoot项目公共配置

## 依赖包引入

```xml
<dependencies>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <version>2.7+</version>
  </dependency>
  <dependency>
    <groupId>com.baomidou</groupId>
    <artifactId>mybatis-plus-boot-starter</artifactId>
    <version>3.5+</version>
  </dependency>
  <dependency>
    <groupId>cn.hutool</groupId>
    <artifactId>hutool-all</artifactId>
    <version>5.8+</version>
  </dependency>
</dependencies>
```

## 引入加解密工具Maven包
```xml
<dependency>
    <groupId>com.sgchen</groupId>
    <artifactId>security-crypto-mybatis</artifactId>
    <version>1.0.45</version>
</dependency>
```

## springBoot启动类加注解

## 配置文件参数

```yaml
csg-security:
   # 数据存储加解密配置
   database:
      enabled: true  # 默认开启，显式关闭数据库加密配置
      secretKey: "testtest12345678" # 算法配置秘钥
      algorithm: "AES_ECB_PKCS7"  # 对应SecretAlgorithm枚举，加解密算法
```

# 二、*数据存储*

## *开发使用方法*
### 配置文件参数
```yaml
csg-security:
  # 数据存储加解密配置
  database:
    enabled: true  # 默认开启，显式关闭数据库加密配置
    secretKey: "testtest12345678" # 算法配置秘钥
    algorithm: "AES_ECB_PKCS7"  # 对应SecretAlgorithm枚举，加解密算法
```

### 实体类(VO、DTO、PO等)配置
```markdown

@EncryptEntity 实体类上注解

@EncryptField 实体类上需要新增 查询 加解密字段注解

```

### 实体类代码样例参考
```java
@Data
@TableName("account")
@EncryptEntity
public class AccountPo {
    /**
     * id
     */
    @TableId(value = "id", type= IdType.AUTO)
    private Integer id;
    /**
     * 账号
     */
    @EncryptField
    private String account;
    /**
     * 密码
     */
    @EncryptField
    private String password;
    /**
     * email
     */
    private String email;
}
```
### Mybatis Mapper文件查询方式
```java
// 使用Mapper.xml查询时单个参数注解
@EncryptParam
List<AccountPo> getInfoByAccount(@EncryptParam("account") @Param("account") String account);

// 当参数是对象时只需要在类上加注解
List<AccountPo> listByFilter(@Param("entity") AccountPo accountPo);

```
### Mybatis Wrapper内置Api调用使用
```java
public List<AccountPo> getInfoByAccount(AccountPo accountPo) {
    EncryptLambdaQueryWrapper<AccountPo> queryWrapper = new EncryptLambdaQueryWrapper<>();
    queryWrapper.eq(AccountPo::getAccount, accountPo.getAccount());
    return accountMapper.selectList(queryWrapper);
}
```
查询时使用 EncryptLambdaQueryWrapper

更新时调用 EncryptLambdaUpdateWrapper

### Mapper层代码样例参考
```java
@Service
public class AccountServiceImpl implements AccountService {


    @Resource
    private AccountMapper accountMapper;

    @Override
    public void addAccount(AccountPo accountPo) {
        accountMapper.insert(accountPo);
    }

    @Override
    public List<AccountPo> queryAllWrapper() {
        return accountMapper.selectList(Wrappers.emptyWrapper());
    }

    @Override
    public void updatePasswordByAccount(String account, String password) {
        accountMapper.updatePasswordByAccount(account, password);
    }

    @Override
    public void updateByIdWrapper(AccountPo accountPo) {
        accountMapper.updateById(accountPo);
    }

    @Override
    public List<AccountPo> getInfoByMapperParams(AccountPo accountPo) {
        return accountMapper.getInfoByAccount(accountPo.getAccount());
    }

    @Override
    public List<AccountPo> getInfoByWrapper(AccountPo accountPo) {
        EncryptLambdaQueryWrapper<AccountPo> queryWrapper = new EncryptLambdaQueryWrapper<>();
        queryWrapper.eq(AccountPo::getAccount, accountPo.getAccount());
        return accountMapper.selectList(queryWrapper);
    }

    @Override
    public List<AccountPo> listByMapperEntity(AccountPo accountPo) {
        return accountMapper.listByFilter(accountPo);
    }

    @Override
    public AccountPo infoByWrapperId(Integer id) {
        return accountMapper.selectById(id);
    }

    @Override
    public void updateByIdUpdateWrapper(AccountPo accountPo) {
        EncryptLambdaUpdateWrapper<AccountPo> queryWrapper = new EncryptLambdaUpdateWrapper<>();
        queryWrapper.eq(AccountPo::getId, accountPo.getId());
        queryWrapper.set(AccountPo::getEmail,accountPo.getEmail());
        queryWrapper.set(AccountPo::getAccount,accountPo.getAccount());
        accountMapper.update(null,queryWrapper);
    }

    @Override
    public void updateUpdateWrapper(AccountPo accountPo) {
        EncryptLambdaQueryWrapper<AccountPo> queryWrapper = new EncryptLambdaQueryWrapper<>();
        queryWrapper.eq(AccountPo::getId, accountPo.getId());
        accountMapper.update(accountPo,queryWrapper);
    }
}
```