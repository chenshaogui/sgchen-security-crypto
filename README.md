# SGChen Security Crypto

Spring Boot 加解密与数据脱敏组件，按功能拆分为以下 Maven 模块：

| 模块 | 功能 |
| --- | --- |
| `security-crypto-core` | 加解密算法、密钥配置、注解和脱敏基础能力 |
| `security-crypto-mybatis` | MyBatis 持久化字段加解密支持 |
| `security-crypto-transfer` | HTTP 请求/响应加解密、接口脱敏及非对称密钥管理 |

## 构建

在项目根目录执行：

```shell
mvn clean install
```

使用持久化加解密时引入 `security-crypto-mybatis`；使用接口传输加解密时引入 `security-crypto-transfer`。两个集成模块会通过 Maven 自动依赖 `security-crypto-core`。

各模块用法和请求样例见对应模块的 `README.md` 及 `security-crypto-transfer/doc/api-request`。
