# 数据传输加解密、接口脱敏
**********
PKCS5->AES_ECB_PKCS5、PKCS7->AES_ECB_PKCS7、CBC_PKCS7->AES_CBC_PKCS7
PKCS5_STRICT->AES_ECB_PKCS5_STRICT、PKCS7_STRICT->AES_ECB_PKCS7_STRICT、CBC_PKCS7_STRICT->AES_CBC_PKCS7_STRICT
**********

**********
请求样例demo见[api-request](doc/api-request)
**********

基于SpringBoot和Mybatis的数据安全处理，接口请求加密解密，接口的脱敏处理。

1、通过实现接口请求和相应数据的解密加密以及敏感数据的脱敏处理

**********
前端秘钥存储可以使用用户密码加密，后端秘钥配置可以用-Djasypt.encryptor.password= 加密存储
**********

SpringBoot+MyBatis-Plus ，HuTool的工具包、Lombok插件以及Bouncy Castle加密包、fastjson2工具

数据传输加解密及数据存储加解密使用手册

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
    <groupId>cn.hutool</groupId>
    <artifactId>hutool-all</artifactId>
    <version>5.8+</version>
  </dependency>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
    <version>2.7+</version>
  </dependency>
</dependencies>
```

## 引入加解密工具Maven包
```xml
<dependency>
    <groupId>com.sgchen</groupId>
    <artifactId>security-crypto-transfer</artifactId>
    <version>1.0.45</version>
</dependency>
```

## 配置文件参数

```yaml
csg-security:
   # 请求传输时加解密配置
   request:
      # 默认开启，可省略；设为false则关闭请求加密配置
      enabled: true
      # 配置秘钥[使用useAsymmetricMode非对称模式时，可不配置]
      secretKey: "01234567"
      # 配置IV[使用useAsymmetricMode非对称模式时，可不配置]
      secretIV: "0102030405060708"
      # 对应SecretAlgorithm枚举，加解密算法
      # 跳过错误模式：AES_ECB_PKCS5、AES_ECB_PKCS7、AES_CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
      # 严格模式：AES_ECB_PKCS5_STRICT、AES_ECB_PKCS7_STRICT、AES_CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
      # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
      algorithm: "CUSTOM_ALGORITHM"
      # 参数加解密模式，FULL全部参数，FIELD单个字段【默认全部】
      transMode: "FIELD"
      customAlgorithm:
         algorithm: "DES/CBC/PKCS5Padding" #其他加解密算法
         skipError: true #加解密失败时，是否跳过
         keySize: 56
         ivSize: 8
      # 使用非对称传输模式，用于加解密秘钥key
      # RSA_WITH_SESSION(RSA 非对称加密混合，秘钥会话模式)、RSA_WITH_HEADER(非对称加密混合，请求头秘钥模式)
      # ECDH_WITH_SESSION(ECDH_WITH_SESSION)、ECDH_WITH_HEADER(ECC 非对称加密模式，请求头秘钥模式)
      # ELGAMAL_WITH_SESSION(ELGAMAL 非对称加密混合，秘钥会话模式)、ELGAMAL_WITH_HEADER(ElGamal 非对称加密模式，请求头秘钥模式)
      # SM2_WITH_SESSION(SM2 非对称加密混合，秘钥会话模式),SM2_WITH_HEADER(SM2 非对称加密模式，请求头秘钥模式)
      # CUSTOM_ALGORITHM(自定义其他算法)，使用时csg-security.request.customSecretKeyAlgorithm必填
      useAsymmetricMode: "SM2_WITH_HEADER"
      customSecretKeyAlgorithm:
         algorithm: "RSA"
         description: "RSA，1024大小的算法"
         transMode: "SESSION" #传输秘钥加解密模式，SESSION会话模式，HEADER请求头携带秘钥(默认)
         keySize: 1024
      clientCode: "PLATFORM-001" # 使用非对称传输模式，用于独立不同的业务模块
```


# 二、传输不加密时，脱敏字段

## *开发使用方法*

### Controller层类注解
```java
@DesensitizedRequest({
        @DesensitizedUnit(field = "secondPhone", mode = DesensitizedMode.mobile),
        @DesensitizedUnit(field = "secondReceiver", mode = DesensitizedMode.name),
        @DesensitizedUnit(field = "auditor", mode = DesensitizedMode.name),
        @DesensitizedUnit(field = "secondAddress", mode = DesensitizedMode.address),
        @DesensitizedUnit(field = "userAccount", mode = DesensitizedMode.mobile)
})
public class AccountController {}
```

### Controller层方法上注解)
```java
@DesensitizedMethod({
        @DesensitizedUnit(field = "secondPhone", mode = DesensitizedMode.mobile),
        @DesensitizedUnit(field = "secondReceiver", mode = DesensitizedMode.name),
        @DesensitizedUnit(field = "auditor", mode = DesensitizedMode.name),
        @DesensitizedUnit(field = "secondAddress", mode = DesensitizedMode.address),
        @DesensitizedUnit(field = "userAccount", mode = DesensitizedMode.mobile)
})
public AjaxResult queryAllWrapper() {}
```

#  三、数据传输

## *开发使用方法(包含数据脱敏)*

### Controller层类注解：类注解方式(方法和类注解方式二选一)
```java
@EncryptController(
        value = { //返回响应数据对字段脱敏
                @DesensitizedUnit(field = "secondPhone", mode = DesensitizedMode.mobile),
                @DesensitizedUnit(field = "secondReceiver", mode = DesensitizedMode.name),
                @DesensitizedUnit(field = "auditor", mode = DesensitizedMode.name),
                @DesensitizedUnit(field = "secondAddress", mode = DesensitizedMode.address),
                @DesensitizedUnit(field = "userAccount", mode = DesensitizedMode.mobile)
        },
        decryptField = { // csg-security.request.transMode=FIELD,解密请求body的参数
                @ReqDecryptField(field = "account"),
                @ReqDecryptField(field = "userName"),
                @ReqDecryptField(field = "test")
        }
)
public class AccountController {}
```

### Controller层方法注解：方法上的加密请求注解(方法和类注解方式二选一)
```java
@EncryptRequest(
        value = { //返回响应数据对字段脱敏
                @DesensitizedUnit(field = "secondPhone", mode = DesensitizedMode.mobile),
                @DesensitizedUnit(field = "secondReceiver", mode = DesensitizedMode.name),
                @DesensitizedUnit(field = "auditor", mode = DesensitizedMode.name),
                @DesensitizedUnit(field = "secondAddress", mode = DesensitizedMode.address),
                @DesensitizedUnit(field = "userAccount", mode = DesensitizedMode.mobile)
        },
        decryptField = { // csg-security.request.transMode=FIELD,解密请求body的参数
                @ReqDecryptField(field = "account"),
                @ReqDecryptField(field = "userName"),
                @ReqDecryptField(field = "test")
        }
)
public AjaxResult queryAllWrapper() {}
```

### 单个字段加密模式，返回实体类数据加密
```java
@RspEncryptField
private String account;

@RspEncryptEntity
private StudentAccount studentAccount;
```

## *配置文件参数配置*

### 对称和非对称自定义加密

使用其他对称加密算法
```yaml
csg-security:
  # 请求传输时加解密配置
  request:
    # 默认开启，可省略；设为false则关闭请求加密配置
    enabled: true
    # 配置秘钥[使用useAsymmetricMode非对称模式时，可不配置]
    secretKey: "01234567"
    # 配置IV[使用useAsymmetricMode非对称模式时，可不配置]
    secretIV: "0102030405060708"
    # 对应SecretAlgorithm枚举，加解密算法
    # 跳过错误模式：AES_ECB_PKCS5、AES_ECB_PKCS7、AES_CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
    # 严格模式：AES_ECB_PKCS5_STRICT、AES_ECB_PKCS7_STRICT、AES_CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
    # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
    algorithm: "CUSTOM_ALGORITHM"
    # 参数加解密模式，FULL全部参数，FIELD单个字段【默认全部】
    transMode: "FIELD"
    customAlgorithm:
      algorithm: "DES/CBC/PKCS5Padding" #其他加解密算法
      skipError: true #加解密失败时，是否跳过
      keySize: 56
      ivSize: 8
    # 使用非对称传输模式，用于加解密秘钥key
    # RSA_WITH_SESSION(RSA 非对称加密混合，秘钥会话模式)、RSA_WITH_HEADER(非对称加密混合，请求头秘钥模式)
    # ECDH_WITH_SESSION(ECDH_WITH_SESSION)、ECDH_WITH_HEADER(ECC 非对称加密模式，请求头秘钥模式)
    # ELGAMAL_WITH_SESSION(ELGAMAL 非对称加密混合，秘钥会话模式)、ELGAMAL_WITH_HEADER(ElGamal 非对称加密模式，请求头秘钥模式)
    # SM2_WITH_SESSION(SM2 非对称加密混合，秘钥会话模式),SM2_WITH_HEADER(SM2 非对称加密模式，请求头秘钥模式)
    # CUSTOM_ALGORITHM(自定义其他算法)，使用时csg-security.request.customSecretKeyAlgorithm必填
    useAsymmetricMode: "CUSTOM_ALGORITHM"
    customSecretKeyAlgorithm:
      algorithm: "RSA"
      description: "RSA，1024大小的算法"
      transMode: "SESSION" #传输秘钥加解密模式，SESSION会话模式，HEADER请求头携带秘钥(默认)
      keySize: 1024
    clientCode: "PLATFORM-001" # 使用非对称传输模式，用于独立不同的业务模块
```

### Feign调用时使用方法
```java
@Configuration
public class FeignRequestInterceptor implements RequestInterceptor {

    @Bean
    public feign.Logger.Level loggerLevel() {
        return feign.Logger.Level.FULL;
    }

    @Override
    public void apply(RequestTemplate requestTemplate) {
        requestTemplate.header(SecurityConstants.FEIGN_CLIENT_CALL, "true");
        // to do something 
    }
}
```
### 对称加密【ECB(无IV)模式】: AES、SM4、自定义对称加密

#### 加解密流程

1.请求使用固定秘钥加密的数据传输
客户端 → 发送【固定秘钥加密 的请求数据】→ 服务端
服务端 → 固定秘钥加密解密请求数据 → 处理业务 → 用客户端固定秘钥加密响应 → 返回客户端

#### 使用方法

* 1、项目秘钥配置【使用AES/ECB/PKCS7Padding秘钥为例】
```yaml
csg-security:
  # 请求传输时加解密配置
  request:
    # 默认开启，可省略；设为false则关闭请求加密配置
    enabled: true
    # 配置秘钥[使用useAsymmetricMode非对称模式时，可不配置]
    secretKey: "请求存储加密秘钥"
    # 对应SecretAlgorithm枚举，加解密算法
    # 跳过错误模式：AES_ECB_PKCS5、AES_ECB_PKCS7、AES_CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
    # 严格模式：AES_ECB_PKCS5_STRICT、AES_ECB_PKCS7_STRICT、AES_CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
    # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
    algorithm: "AES_ECB_PKCS7"
    # 参数加解密模式，FULL全部参数，FIELD单个字段【默认全部】
    transMode: "FULL"
```
* 2、请求数据传输用例(用ApiPost模拟)

|   步骤   | 处理方法                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  参数加密  | <code> const key = CryptoJS.enc.Utf8.parse("0123456789abcdeffedcba9876543210");<br/>//加密方法<br/>function Encrypt(word) {<br/>    let srcs = CryptoJS.enc.Utf8.parse(typeof word === "string" ? word : JSON.stringify(word));<br/>    let encrypted = CryptoJS.AES.encrypt(srcs, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });<br/>    return encrypted.toString();<br/>}<br/>let requests = Encrypt(request.request_bodys);<br/>pm.request.body.raw = requests;                          </code>         |
|  请求数据  | <code>POST: localhost:9898/data-security/account/getInfoByWrapper <br/> RequestBody请求数据:<br/> MCORifq5PMEjU8+q3F9A0nkJSH/iziLmuuL0HIpBk4M=</code>                                                                                                                                                                                                                                                                                                                                                                         |
| 返回数据解密 | <code>const key = CryptoJS.enc.Utf8.parse("0123456789abcdeffedcba9876543210");<br/>//解密方法<br/>function Decrypt(word) {<br/>    let decrypt = CryptoJS.AES.decrypt(word.replaceAll("\"", ""), key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });<br/>    let decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);<br/>    return decryptedStr.toString();<br/>}<br/>let responses = Decrypt(response.raw.responseText);<br/>console.log(JSON.parse(responses))<br/>pm.response.setBody(responses);<br/></code> |

### 对称加密【固定IV】: AES、SM4、自定义对称加密

#### 加解密流程

1.请求使用固定秘钥和固定IV加密的数据传输
客户端 → 发送【固定秘钥和固定IV加密 的请求数据】→ 服务端
服务端 → 固定秘钥和固定IV加密解密请求数据 → 处理业务 → 用客户端固定秘钥和固定IV加密响应 → 返回客户端

#### 使用方法

* 1、项目秘钥配置【使用固定秘钥和固定IV加密为例】
```yaml
csg-security:
  # 请求传输时加解密配置
  request:
    # 默认开启，可省略；设为false则关闭请求加密配置
    enabled: true
    # 配置秘钥[使用useAsymmetricMode非对称模式时，可不配置]
    secretKey: "0123456789abcdeffedcba9876543210"
    # 配置IV[使用useAsymmetricMode非对称模式时，可不配置]
    secretIV: "0102030405060708"
    # 对应SecretAlgorithm枚举，加解密算法
    # 跳过错误模式：AES_ECB_PKCS5、AES_ECB_PKCS7、AES_CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
    # 严格模式：AES_ECB_PKCS5_STRICT、AES_ECB_PKCS7_STRICT、AES_CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
    # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
    algorithm: "AES_CBC_PKCS7"
    # 参数加解密模式，FULL全部参数，FIELD单个字段【默认全部】
    transMode: "FULL"
```


* 2、请求数据传输用例(采用16进制的IV模式，16进制的key，base64的IV请参考：动态Base64编码IV，前端用ApiPost模拟)

|   步骤   | 处理方法                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:------:|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  参数加密  | <code>let key = "0123456789abcdeffedcba9876543210";<br/>const iv = CryptoJS.enc.Utf8.parse('0102030405060708');   //十六位十六进制数作为密钥偏移量<br/>//加密方法<br/>function Encrypt(word) {<br/>    let srcs = CryptoJS.enc.Utf8.parse(typeof word === "string" ? word : JSON.stringify(word));<br/>    key = CryptoJS.enc.Hex.parse(key);<br/>    let encrypted = CryptoJS.AES.encrypt(srcs, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });<br/>    return encrypted.toString();<br/>}<br/>let requests = Encrypt(request.request_bodys);<br/>pm.request.body.raw = requests;<br/></code>        |
|  请求数据  | <code>POST: localhost:9898/data-security/account/getInfoByWrapper <br/>RequestBody请求数据:<br/> aHoFvEIrf7wDCT3jlsCiMizWg5KAu000+fI/HPW7IMY=</code>                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 返回数据解密 | <code>let key = "0123456789abcdeffedcba9876543210";<br/>const iv = CryptoJS.enc.Utf8.parse('0102030405060708');<br/>//解密方法<br/>function Decrypt(word) {<br/>    key = CryptoJS.enc.Hex.parse(key);<br/>    let decrypt = CryptoJS.AES.decrypt(word.replaceAll("\"", ""), key, { mode: CryptoJS.mode.CBC,iv:iv,padding: CryptoJS.pad.Pkcs7 });<br/>    let decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);<br/>    return decryptedStr.toString();<br/>}<br/>let responses = Decrypt(response.raw.responseText);<br/>console.log(JSON.parse(responses))<br/>pm.response.setBody(responses);<br/></code> |

### 对称加密【动态16进制IV】: AES、SM4、自定义对称加密

#### 加解密流程

1.请求使用固定秘钥和动态16进制IV加密的数据传输
客户端 → 发送【固定秘钥和动态16进制IV加密 的请求数据】→ 服务端
服务端 → 固定秘钥和动态16进制IV加密解密请求数据 → 处理业务 → 用客户端固定秘钥和动态16进制IV加密响应 → 返回客户端

#### 使用方法

* 1、项目秘钥配置【使用固定秘钥和动态16进制IV加密为例】
```yaml
csg-security:
  # 请求传输时加解密配置
  request:
    # 默认开启，可省略；设为false则关闭请求加密配置
    enabled: true
    # 配置秘钥[使用useAsymmetricMode非对称模式时，可不配置]
    secretKey: "0123456789abcdeffedcba9876543210"
    # 对应SecretAlgorithm枚举，加解密算法
    # 跳过错误模式：AES_ECB_PKCS5、AES_ECB_PKCS7、AES_CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
    # 严格模式：AES_ECB_PKCS5_STRICT、AES_ECB_PKCS7_STRICT、AES_CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
    # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
    algorithm: "SM4_CBC_PKCS7"
    # 参数加解密模式，FULL全部参数，FIELD单个字段【默认全部】
    transMode: "FULL"
```
* 2、请求数据传输用例(采用16进制的IV模式，16进制的key，base64的IV请参考：动态Base64编码IV，前端用ApiPost模拟)

|   步骤   | 处理方法                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  参数加密  | <code>// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）<br/>var secretKey = "0123456789abcdeffedcba9876543210"; // 必须是16字节（128位）<br/>// 生成 16 字节随机 IV（以 WordArray 格式表示）<br/>const iv = CryptoJS.lib.WordArray.random(16);<br/>// 转换为十六进制字符串（可读性更好）<br/>const ivHex = iv.toString(CryptoJS.enc.Hex);<br/>// 请求前脚本 - SM4加密请求数据并以Base64格式输出<br/>function encryptData(word, key, iv) {<br/>    // 使用SM4-CBC模式加密<br/>    let encryptedHex = sm4.encrypt(word, key, { mode: 'cbc', iv: iv }) // 加密，cbc 模式<br/>    // 将16进制字符串转换为字节数组<br/>    var bytes = hexToBytes(encryptedHex);<br/>    // 将字节数组转换为Base64<br/>    var encryptedBase64 = bytesToBase64(bytes);<br/>    return encryptedBase64;<br/>}<br/><br/>// 辅助函数：16进制字符串转字节数组<br/>function hexToBytes(hex) {<br/>    var bytes = [];<br/>    for (var i = 0; i < hex.length; i += 2) {<br/>        bytes.push(parseInt(hex.substr(i, 2), 16));<br/>    }<br/>    return bytes;<br/>}<br/>// 辅助函数：字节数组转Base64<br/>function bytesToBase64(bytes) {<br/>    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';<br/>    var result = '';<br/>    var i = 0;<br/><br/>    while (i < bytes.length) {<br/>        var byte1 = bytes[i++];<br/>        var byte2 = i < bytes.length ? bytes[i++] : 0;<br/>        var byte3 = i < bytes.length ? bytes[i++] : 0;<br/><br/>        var enc1 = byte1 >> 2;<br/>        var enc2 = ((byte1 & 0x03) << 4) \| (byte2 >> 4);<br/>        var enc3 = ((byte2 & 0x0F) << 2) \| (byte3 >> 6);<br/>        var enc4 = byte3 & 0x3F;<br/><br/>        if (i > bytes.length + 1) {<br/>            enc3 = enc4 = 64;<br/>        } else if (i > bytes.length) {<br/>            enc4 = 64;<br/>        }<br/><br/>        result += base64Chars.charAt(enc1) + base64Chars.charAt(enc2) +<br/>            base64Chars.charAt(enc3) + base64Chars.charAt(enc4);<br/>    }<br/><br/>    return result;<br/>}<br/><br/>// 获取请求数据<br/>var requestData = pm.request.body.raw;<br/>// 加密数据<br/>var encryptedData = encryptData(requestData, secretKey, ivHex);<br/>// 设置加密后的数据到请求体<br/>pm.request.body.raw = encryptedData;<br/>// 可选：添加加密信息头<br/>pm.request.headers.upsert({<br/>    key: 'X-Encrypted-IV',<br/>    value: ivHex<br/>});<br/></code>                                                                                                                                                                                    |
|  请求数据  | <code>POST: localhost:9898/data-security/account/getInfoByWrapper <br/>RequestBody请求数据:<br/>4mDrMKIsb7soAEDD/d6QvmaHwIOB3cbkygUmJlp1KTgRT4qVYy5giiSFwtDD1KB+</code>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 返回数据解密 | <code>// 响应后脚本 - 解密SM4加密的响应数据<br/>// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）<br/>var secretKey = "0123456789abcdeffedcba9876543210"; // 必须是16字节（128位）<br/>function decryptData(ciphertext, key, iv) {<br/>    // 使用SM4-CBC模式解密<br/>    let decryptStr = ciphertext.replaceAll("\"", "");<br/>    // 将Base64转换为字节数组<br/>    var ciphertextBytes = base64ToBytes(decryptStr);<br/>    // 将字节数组转换为16进制字符串<br/>    var ciphertextHex = bytesToHex(ciphertextBytes);<br/>    // key = CryptoJS.enc.Hex.parse(key);<br/>    // 使用SM4-CBC模式加密<br/>    var decryptedResult = sm4.decrypt(ciphertextHex, key, { mode: 'cbc', iv: iv })<br/>    return decryptedResult;<br/>}<br/><br/>// 辅助函数：Base64转字节数组<br/>function base64ToBytes(base64) {<br/>    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';<br/>    base64 = base64.replace(/=+$/, '');<br/><br/>    var bytes = [];<br/>    for (var i = 0; i < base64.length; i += 4) {<br/>        var enc1 = base64Chars.indexOf(base64.charAt(i));<br/>        var enc2 = base64Chars.indexOf(base64.charAt(i + 1));<br/>        var enc3 = base64Chars.indexOf(base64.charAt(i + 2));<br/>        var enc4 = base64Chars.indexOf(base64.charAt(i + 3));<br/><br/>        var byte1 = (enc1 << 2) \| (enc2 >> 4);<br/>        var byte2 = ((enc2 & 0x0F) << 4) \| (enc3 >> 2);<br/>        var byte3 = ((enc3 & 0x03) << 6) \| enc4;<br/><br/>        bytes.push(byte1);<br/>        if (enc3 !== 64) bytes.push(byte2);<br/>        if (enc4 !== 64) bytes.push(byte3);<br/>    }<br/><br/>    return bytes;<br/>}<br/>// 辅助函数：字节数组转16进制字符串<br/>function bytesToHex(bytes) {<br/>    var hex = [];<br/>    for (var i = 0; i < bytes.length; i++) {<br/>        var b = bytes[i];<br/>        hex.push((b < 16 ? '0' : '') + b.toString(16));<br/>    }<br/>    return hex.join('');<br/>}<br/><br/>// 获取响应数据<br/>var responseData = pm.response.text();<br/>const envIV = pm.response.headers.get('X-Encrypted-IV');<br/>// 解密数据<br/>var decryptedData = decryptData(responseData, secretKey, envIV);<br/>// 尝试解析为JSON（如果是JSON格式）<br/>try {<br/>    var jsonData = JSON.parse(decryptedData);<br/>    pm.response.json = function () { return jsonData; };<br/>} catch (e) {<br/>    // 如果不是JSON，保留原始解密文本<br/>    pm.response.text = function () { return decryptedData; };<br/>}<br/><br/>// 记录解密结果到控制台<br/>console.log("解密响应:", decryptedData);<br/></code> |

### 对称加密【动态Base64编码IV】: AES、SM4、自定义对称加密

#### 加解密流程

1.请求使用固定秘钥和动态base64编码IV加密的数据传输
客户端 → 发送【固定秘钥和动态base64编码IV加密 的请求数据】→ 服务端
服务端 → 固定秘钥和动态base64编码IV加密解密请求数据 → 处理业务 → 用客户端固定秘钥和动态base64编码IV加密响应 → 返回客户端

#### 使用方法

* 1、项目秘钥配置【使用固定秘钥和base64编码IV加密为例】
```yaml
csg-security:
  # 请求传输时加解密配置
  request:
    # 默认开启，可省略；设为false则关闭请求加密配置
    enabled: true
    # 配置秘钥[使用useAsymmetricMode非对称模式时，可不配置]
    secretKey: "0123456789abcdeffedcba9876543210"
    # 对应SecretAlgorithm枚举，加解密算法
    # 跳过错误模式：AES_ECB_PKCS5、AES_ECB_PKCS7、AES_CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
    # 严格模式：AES_ECB_PKCS5_STRICT、AES_ECB_PKCS7_STRICT、AES_CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
    # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
    algorithm: "AES_CBC_PKCS7"
    # 参数加解密模式，FULL全部参数，FIELD单个字段【默认全部】
    transMode: "FULL"
```

* 2、请求数据传输用例(采用动态Base64编码的IV模式，16进制的key，前端用ApiPost模拟)

|   步骤   | 处理方法                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  参数加密  | <code>// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）<br/>var secretKey = "0123456789abcdeffedcba9876543210"; // 必须是16字节（128位）<br/>// 生成 16 字节随机 IV（以 WordArray 格式表示）<br/>var iv = CryptoJS.lib.WordArray.random(16);<br/>// 转换为 Base64 字符串（适合在 HTTP 请求头中传输）<br/>var ivBase64 = iv.toString(CryptoJS.enc.Base64);<br/>// 转换为十六进制字符串（可读性更好）<br/>var ivHex = iv.toString(CryptoJS.enc.Hex);<br/>// 请求前脚本 - SM4加密请求数据并以Base64格式输出<br/>function encryptData(word, key, iv) {<br/>    let srcs = CryptoJS.enc.Utf8.parse(typeof word === "string" ? word : JSON.stringify(word));<br/>    let keyStr = CryptoJS.enc.Utf8.parse(key);<br/>    keyStr = CryptoJS.enc.Hex.parse(key);<br/>    let ivstr = CryptoJS.enc.Base64.parse(iv);<br/>    let encrypted = CryptoJS.AES.encrypt(srcs, keyStr, { iv: ivstr, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });<br/>    console.log("加密字符串", encrypted.toString())<br/>    return encrypted.toString();<br/>}<br/><br/>// 辅助函数：16进制字符串转字节数组<br/>function hexToBytes(hex) {<br/>    var bytes = [];<br/>    for (var i = 0; i < hex.length; i += 2) {<br/>        bytes.push(parseInt(hex.substr(i, 2), 16));<br/>    }<br/>    return bytes;<br/>}<br/>// 辅助函数：字节数组转Base64<br/>function bytesToBase64(bytes) {<br/>    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';<br/>    var result = '';<br/>    var i = 0;<br/><br/>    while (i < bytes.length) {<br/>        var byte1 = bytes[i++];<br/>        var byte2 = i < bytes.length ? bytes[i++] : 0;<br/>        var byte3 = i < bytes.length ? bytes[i++] : 0;<br/><br/>        var enc1 = byte1 >> 2;<br/>        var enc2 = ((byte1 & 0x03) << 4) \| (byte2 >> 4);<br/>        var enc3 = ((byte2 & 0x0F) << 2) \| (byte3 >> 6);<br/>        var enc4 = byte3 & 0x3F;<br/><br/>        if (i > bytes.length + 1) {<br/>            enc3 = enc4 = 64;<br/>        } else if (i > bytes.length) {<br/>            enc4 = 64;<br/>        }<br/><br/>        result += base64Chars.charAt(enc1) + base64Chars.charAt(enc2) +<br/>            base64Chars.charAt(enc3) + base64Chars.charAt(enc4);<br/>    }<br/><br/>    return result;<br/>}<br/>// 获取请求数据<br/>var requestData = pm.request.body.raw;<br/>var encryptedData = encryptData(requestData, secretKey, ivBase64);<br/>// 设置加密后的数据到请求体<br/>pm.request.body.raw = encryptedData;<br/>// 可选：添加加密信息头<br/>pm.request.headers.upsert({<br/>    key: 'X-Encrypted-IV',<br/>    value: ivBase64<br/>});<br/></code> |
|  请求数据  | <code>POST: localhost:9898/data-security/account/getInfoByWrapper <br/>RequestBody请求数据:<br/>CbWiLmLavpkTaEglW9pNdCocnhQDiI5Ewt+6evPNBtnjBTOKub3szj10FMPf0yEw</code>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 返回数据解密 | <code>// 响应后脚本 - 解密SM4加密的响应数据<br/>// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）<br/>var secretKey = "0123456789abcdeffedcba9876543210"; // 必须是16字节（128位）<br/>function decryptData(ciphertext, key, iv) {<br/>    let decryptStr = ciphertext.replaceAll("\"", "");<br/>    let keyStr = CryptoJS.enc.Utf8.parse(key);<br/>    keyStr = CryptoJS.enc.Hex.parse(key);<br/>    let ivstr = CryptoJS.enc.Base64.parse(iv);<br/>    var decryptedResult = CryptoJS.AES.decrypt(decryptStr, keyStr, { iv: ivstr, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });<br/>    let decryptedStr = CryptoJS.enc.Utf8.stringify(decryptedResult);<br/>    return decryptedStr.toString();<br/>}<br/><br/>// 获取响应数据<br/>var responseData = pm.response.text();<br/>const envIV = pm.response.headers.get('X-Encrypted-IV');<br/>// 解密数据<br/>var decryptedData = decryptData(responseData, secretKey, envIV);<br/>// 尝试解析为JSON（如果是JSON格式）<br/>try {<br/>    var jsonData = JSON.parse(decryptedData);<br/>    pm.response.json = function () { return jsonData; };<br/>} catch (e) {<br/>    // 如果不是JSON，保留原始解密文本<br/>    pm.response.text = function () { return decryptedData; };<br/>}<br/><br/>// 记录解密结果到控制台<br/>console.log("解密响应:", decryptedData);<br/></code>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

### 非对称加密混合请求头秘钥模式【秘钥对称加密、传输数据非对称加密】: RSA、SM2、ECC(ECDH、ECDSA)、ElGamal、自定义非对称加密

#### 加解密流程(需要Redis支持)

1. 首次创建会话时传输对称密钥
   客户端 → 生成对称密钥

2.请求携带客户端秘钥以及客户端秘钥加密的数据
客户端 → 发送【客户端秘钥加密的数据 + 非对称加密客户端秘钥 的请求数据】→ 服务端
服务端 → 用公钥解密客户端密钥 → 使用客户端秘钥解密请求数据 → 处理业务 → 用客户端秘钥加密响应 → 返回客户端

#### 默认参数配置(非对称密钥对有效期)

```yaml
# 混合加密模式
csg-tsc:
  rsa-key:
    # RSA密钥有效期(小时)，默认24小时
    expiryHours: 24
```

当没有配置数据时将使用默认配置

#### 使用方法(多项目共用一个Redis，客户端编码必须配置)

* 1、项目秘钥配置【使用SM4加密传输数据，SM2传输秘钥为例】
```yaml
csg-security:
  # 请求传输时加解密配置
  request:
    # 默认开启，可省略；设为false则关闭请求加密配置
    enabled: true
    # 对应SecretAlgorithm枚举，加解密算法
    # 跳过错误模式：AES_ECB_PKCS5、AES_ECB_PKCS7、AES_CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
    # 严格模式：AES_ECB_PKCS5_STRICT、AES_ECB_PKCS7_STRICT、AES_CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
    # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
    algorithm: "SM4_CBC_PKCS7"
    # 参数加解密模式，FULL全部参数，FIELD单个字段【默认全部】
    transMode: "FULL"
    # 使用非对称传输模式，用于加解密秘钥key
    # RSA_WITH_SESSION(RSA 非对称加密混合，秘钥会话模式)、RSA_WITH_HEADER(非对称加密混合，请求头秘钥模式)
    # ECDH_WITH_SESSION(ECDH_WITH_SESSION)、ECDH_WITH_HEADER(ECC 非对称加密模式，请求头秘钥模式)
    # ELGAMAL_WITH_SESSION(ELGAMAL 非对称加密混合，秘钥会话模式)、ELGAMAL_WITH_HEADER(ElGamal 非对称加密模式，请求头秘钥模式)
    # SM2_WITH_SESSION(SM2 非对称加密混合，秘钥会话模式),SM2_WITH_HEADER(SM2 非对称加密模式，请求头秘钥模式)
    # CUSTOM_ALGORITHM(自定义其他算法)，使用时csg-security.request.customSecretKeyAlgorithm必填
    useAsymmetricMode: "SM2_WITH_HEADER"
    clientCode: "PLATFORM-001" # 使用非对称传输模式，用于独立不同的业务模块
```

* 2、前端获取公钥

```html
Get: localhost:9898/data-security/api/asymmetricTSC/public-key
Response响应数据:
{
    "publicKey": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEFgFkoXDTKyP2jhigRUlrI3qO0LxZ3emioBNS8ReMYW19PMSEw+90mWmWBDcF8h0eUwDmpMWaXApfX2vRWWfwtw==",
    "version": "c72255c86c5f4993b39dea9458140fd7"
}
```
* 3、前端使用公钥加密私钥

--自定义方法处理

* 4、请求数据传输用例(采用16进制的IV模式，base64的IV请参考：动态Base64编码IV，前端用ApiPost模拟)

|   步骤   | 处理方法                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:------:|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  参数加密  | <code>// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）<br/>var secretKey = "0123456789abcdeffedcba7896543210"; // 必须是16字节（128位）<br/>// 生成 16 字节随机 IV（以 WordArray 格式表示）<br/>var iv = CryptoJS.lib.WordArray.random(16);<br/>// 转换为 Base64 字符串（适合在 HTTP 请求头中传输）<br/>// 转换为十六进制字符串（可读性更好）<br/>var ivHex = iv.toString(CryptoJS.enc.Hex);<br/>// 请求前脚本 - SM4加密请求数据并以Base64格式输出<br/>function encryptData(word, key, iv) {<br/>    // 如果数据是对象，转换为JSON字符串<br/>    // 使用SM4-CBC模式加密<br/>    let encryptedHex = sm4.encrypt(word, key, { mode: 'cbc', iv: iv }) // 加密，cbc 模式<br/>    // 将16进制字符串转换为字节数组<br/>    var bytes = hexToBytes(encryptedHex);<br/>    // 将字节数组转换为Base64<br/>    var encryptedBase64 = bytesToBase64(bytes);<br/>    return encryptedBase64;<br/>}<br/><br/>// 辅助函数：16进制字符串转字节数组<br/>function hexToBytes(hex) {<br/>    var bytes = [];<br/>    for (var i = 0; i < hex.length; i += 2) {<br/>        bytes.push(parseInt(hex.substr(i, 2), 16));<br/>    }<br/>    return bytes;<br/>}<br/>// 辅助函数：字节数组转Base64<br/>function bytesToBase64(bytes) {<br/>    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';<br/>    var result = '';<br/>    var i = 0;<br/><br/>    while (i < bytes.length) {<br/>        var byte1 = bytes[i++];<br/>        var byte2 = i < bytes.length ? bytes[i++] : 0;<br/>        var byte3 = i < bytes.length ? bytes[i++] : 0;<br/><br/>        var enc1 = byte1 >> 2;<br/>        var enc2 = ((byte1 & 0x03) << 4) \| (byte2 >> 4);<br/>        var enc3 = ((byte2 & 0x0F) << 2) \| (byte3 >> 6);<br/>        var enc4 = byte3 & 0x3F;<br/><br/>        if (i > bytes.length + 1) {<br/>            enc3 = enc4 = 64;<br/>        } else if (i > bytes.length) {<br/>            enc4 = 64;<br/>        }<br/><br/>        result += base64Chars.charAt(enc1) + base64Chars.charAt(enc2) +<br/>            base64Chars.charAt(enc3) + base64Chars.charAt(enc4);<br/>    }<br/><br/>    return result;<br/>}<br/>// 获取请求数据<br/>var requestData = pm.request.body.raw;<br/>var encryptedData = encryptData(requestData, secretKey, ivHex);<br/>// 设置加密后的数据到请求体<br/>pm.request.body.raw = encryptedData;<br/>// 可选：添加加密信息头<br/>pm.request.headers.upsert({<br/>    key: 'X-Encrypted-IV',<br/>    value: ivHex<br/>});<br/></code>                                                                            |
|  请求数据  | <code>POST: localhost:9898/data-security/account/getInfoByWrapper <br/>Header:   X-Encrypted-ClientKey: BOv9lA7TLM358HTgsMa/0c3iPu8k+UShdw0H1iwMqqFBf+V/s7pplR7jT2cdUBYfRhj8fbeOI/dgy2/VVqG8e5qA/fDAVwKQmI0u0MuqNGoHg48UGhCbKwxzwk24cSZj0eZkO58B7v10kB1+sARE7hsSFbn+r8OAuSOwhSeoxGG8 <br/>RequestBody请求数据:<br/> lelKWOI+fJO/6XrTnjqZqWeppGuC6zn+hK40W5pYKuv0ma/O3EFx7VXxI+geBdjV <br/>ResponseBody: "tHgZ5ENlVhWq6QGmaaNRJy/DjU+1datQ2EiteFD9fAltwRR8EwX3gzROm1HwCa4hq8GOS+JMa64kcgrYzZ1WPRvqCw+Y6jEeOcgiNAxCAchN23Mv/dob0aeM4CwI5pzx1QGBsGJeTLle5Dv9oDkTyg=="</code>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 返回数据解密 | <code>// 响应后脚本 - 解密SM4加密的响应数据<br/>// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）<br/>var secretKey = "0123456789abcdeffedcba7896543210"; // 必须是16字节（128位）<br/>function decryptData(ciphertext, key, iv) {<br/>    // 使用SM4-CBC模式解密<br/>    let decryptStr = ciphertext.replaceAll("\"", "");<br/>    // 将Base64转换为字节数组<br/>    var ciphertextBytes = base64ToBytes(decryptStr);<br/>    // 将字节数组转换为16进制字符串<br/>    var ciphertextHex = bytesToHex(ciphertextBytes);<br/>    // 使用SM4-CBC模式加密<br/>    var decryptedResult = sm4.decrypt(ciphertextHex, key, { mode: 'cbc', iv: iv })<br/>    return decryptedResult;<br/>}<br/>// 辅助函数：Base64转字节数组<br/>function base64ToBytes(base64) {<br/>    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';<br/>    base64 = base64.replace(/=+$/, '');<br/>    var bytes = [];<br/>    for (var i = 0; i < base64.length; i += 4) {<br/>        var enc1 = base64Chars.indexOf(base64.charAt(i));<br/>        var enc2 = base64Chars.indexOf(base64.charAt(i + 1));<br/>        var enc3 = base64Chars.indexOf(base64.charAt(i + 2));<br/>        var enc4 = base64Chars.indexOf(base64.charAt(i + 3));<br/><br/>        var byte1 = (enc1 << 2) \| (enc2 >> 4);<br/>        var byte2 = ((enc2 & 0x0F) << 4) \| (enc3 >> 2);<br/>        var byte3 = ((enc3 & 0x03) << 6) \| enc4;<br/><br/>        bytes.push(byte1);<br/>        if (enc3 !== 64) bytes.push(byte2);<br/>        if (enc4 !== 64) bytes.push(byte3);<br/>    }<br/><br/>    return bytes;<br/>}<br/>// 辅助函数：字节数组转16进制字符串<br/>function bytesToHex(bytes) {<br/>    var hex = [];<br/>    for (var i = 0; i < bytes.length; i++) {<br/>        var b = bytes[i];<br/>        hex.push((b < 16 ? '0' : '') + b.toString(16));<br/>    }<br/>    return hex.join('');<br/>}<br/><br/>// 获取响应数据<br/>var responseData = pm.response.text();<br/>const envIV = pm.response.headers.get('X-Encrypted-IV');<br/>// 解密数据<br/>var decryptedData = decryptData(responseData, secretKey, envIV);<br/>// 尝试解析为JSON（如果是JSON格式）<br/>try {<br/>    var jsonData = JSON.parse(decryptedData);<br/>    pm.response.json = function () { return jsonData; };<br/>} catch (e) {<br/>    // 如果不是JSON，保留原始解密文本<br/>    pm.response.text = function () { return decryptedData; };<br/>}<br/><br/>// 记录解密结果到控制台<br/>console.log("解密响应:", decryptedData);<br/></code> |

### 非对称加密混合会话模式【秘钥对称加密、传输数据非对称加密】: RSA、SM2、ECC(ECDH、ECDSA)、ElGamal、自定义非对称加密

#### 加解密流程(需要Redis支持)

1. 首次创建会话时传输对称密钥
   客户端 → 生成对称密钥 → 用服务端公钥加密 → 发送【加密的对称密钥】→ 服务端
   服务端 → 用私钥解密对称密钥 → 生成会话ID → 存储【会话ID → 对称密钥】到Redis → 返回会话ID给客户端

2. 后续请求仅携带会话ID
   客户端 → 发送【会话ID + 用客户端秘钥加密的请求数据】→ 服务端
   服务端 → 用会话ID从Redis获取客户端密钥 → 解密请求数据 → 处理业务 → 用客户端秘钥加密响应 → 返回客户端

#### 默认参数配置（非对称密钥对、会话有效期，会话数和限流配置）

```yaml
# 混合加密模式
csg-tsc:
  rsa-key:
    # 密钥有效期(小时)，默认24小时
    expiryHours: 24
  rsa-session:
    # 最大会话数,默认100000
    maxCount: 100000
    # 会话过期时间，单位秒，默认8小时过期
    expirySeconds: 28800
    # 每个IP每分钟最多允许1000次请求，默认1000
    ipRateLimit: 1000
    # 如果设置为 60 秒，表示统计最近 60 秒内的请求次数. 默认60
    ipRateWindow: 60
```

当没有配置数据时将使用默认配置

#### 使用方法(多项目共用一个Redis，客户端编码必须配置)

* 1、项目秘钥配置【使用SM4加密传输数据，SM2传输秘钥为例】

```yaml
csg-security:
  # 请求传输时加解密配置
  request:
    # 默认开启，可省略；设为false则关闭请求加密配置
    enabled: true
    # 对应SecretAlgorithm枚举，加解密算法
    # 跳过错误模式：PKCS5、PKCS7、CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
    # 严格模式：PKCS5_STRICT、PKCS7_STRICT、CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
    # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
    algorithm: "SM4_CBC_PKCS7"
    # 参数加解密模式，FULL全部参数，FIELD单个字段【默认全部】
    transMode: "FULL"
    # 使用非对称传输模式，用于加解密秘钥key
    # RSA_WITH_SESSION(RSA 非对称加密混合，秘钥会话模式)、RSA_WITH_HEADER(非对称加密混合，请求头秘钥模式)
    # ECDH_WITH_SESSION(ECDH_WITH_SESSION)、ECDH_WITH_HEADER(ECC 非对称加密模式，请求头秘钥模式)
    # ELGAMAL_WITH_SESSION(ELGAMAL 非对称加密混合，秘钥会话模式)、ELGAMAL_WITH_HEADER(ElGamal 非对称加密模式，请求头秘钥模式)
    # SM2_WITH_SESSION(SM2 非对称加密混合，秘钥会话模式),SM2_WITH_HEADER(SM2 非对称加密模式，请求头秘钥模式)
    # CUSTOM_ALGORITHM(自定义其他算法)，使用时csg-security.request.customSecretKeyAlgorithm必填
    useAsymmetricMode: "SM2_WITH_SESSION"
    clientCode: "PLATFORM-001" # 使用非对称传输模式，用于独立不同的业务模块
```

* 2、前端获取公钥

```html
Get: localhost:9898/data-security/api/asymmetricTSC/public-key
Response响应数据:
{
    "publicKey": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEFgFkoXDTKyP2jhigRUlrI3qO0LxZ3emioBNS8ReMYW19PMSEw+90mWmWBDcF8h0eUwDmpMWaXApfX2vRWWfwtw==",
    "version": "c72255c86c5f4993b39dea9458140fd7"
}
```
* 3、前端使用公钥加密私钥

--自定义方法处理

* 4、获取请求会话

```html
Post: localhost:9898/data-security/api/asymmetricTSC/create-session
Header请求头:
    X-Client-Key:BLhIkXkGvHfPaTZq8MmWXys3BVa2bznqS0j/seGtmHYSqbcU1kUKtG2RnhtXbNoq8xD+HIsImQKyqPTz8KIGiqY9gvDEPuVFxpI/lZAI2rbT3yflfgOWG7OfLRn54q0Y6zhb6vKIzWJfup5RW1RqFUiItikGkh+z9JA5PY+mo7de
    X-Timestamp: 1752459639000
Response响应数据:
{
    "expiresIn": 7789,
    "publicKeyVersion": "c72255c86c5f4993b39dea9458140fd7",
    "sessionId": "224a47ff805f41738c1f78e160c6534e"
}
```
* 5、请求数据传输用例(采用16进制的IV模式，base64的IV请参考：动态Base64编码IV，前端用ApiPost模拟)

|   步骤   | 处理方法                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  参数加密  | <code>// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）<br/>var secretKey = "0123456789abcdeffedcba7896543210"; // 必须是16字节（128位）<br/>// 生成 16 字节随机 IV（以 WordArray 格式表示）<br/>var iv = CryptoJS.lib.WordArray.random(16);<br/>// 转换为十六进制字符串（可读性更好）<br/>var ivHex = iv.toString(CryptoJS.enc.Hex);<br/>// 请求前脚本 - SM4加密请求数据并以Base64格式输出<br/>function encryptData(word, key, iv) {<br/>    // 如果数据是对象，转换为JSON字符串<br/>    // 使用SM4-CBC模式加密<br/>    let encryptedHex = sm4.encrypt(word, key, { mode: 'cbc', iv: iv }) // 加密，cbc 模式<br/>    // 将16进制字符串转换为字节数组<br/>    var bytes = hexToBytes(encryptedHex);<br/>    // 将字节数组转换为Base64<br/>    var encryptedBase64 = bytesToBase64(bytes);<br/>    return encryptedBase64;<br/>}<br/><br/>// 辅助函数：16进制字符串转字节数组<br/>function hexToBytes(hex) {<br/>    var bytes = [];<br/>    for (var i = 0; i < hex.length; i += 2) {<br/>        bytes.push(parseInt(hex.substr(i, 2), 16));<br/>    }<br/>    return bytes;<br/>}<br/>// 辅助函数：字节数组转Base64<br/>function bytesToBase64(bytes) {<br/>    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';<br/>    var result = '';<br/>    var i = 0;<br/><br/>    while (i < bytes.length) {<br/>        var byte1 = bytes[i++];<br/>        var byte2 = i < bytes.length ? bytes[i++] : 0;<br/>        var byte3 = i < bytes.length ? bytes[i++] : 0;<br/><br/>        var enc1 = byte1 >> 2;<br/>        var enc2 = ((byte1 & 0x03) << 4) \| (byte2 >> 4);<br/>        var enc3 = ((byte2 & 0x0F) << 2) \| (byte3 >> 6);<br/>        var enc4 = byte3 & 0x3F;<br/><br/>        if (i > bytes.length + 1) {<br/>            enc3 = enc4 = 64;<br/>        } else if (i > bytes.length) {<br/>            enc4 = 64;<br/>        }<br/><br/>        result += base64Chars.charAt(enc1) + base64Chars.charAt(enc2) +<br/>            base64Chars.charAt(enc3) + base64Chars.charAt(enc4);<br/>    }<br/><br/>    return result;<br/>}<br/>// 获取请求数据<br/>var requestData = pm.request.body.raw;<br/>let encryptedData = encryptData(requestData, secretKey, ivHex);<br/>// 设置加密后的数据到请求体<br/>pm.request.body.raw = encryptedData;<br/>// 可选：添加加密信息头<br/>pm.request.headers.upsert({<br/>    key: 'X-Encrypted-IV',<br/>    value: ivHex<br/>});</code>                                                                                                         |
|  请求数据  | <code>POST: localhost:9898/data-security/account/getInfoByWrapper <br/>Header:   X-Encrypted-SessionId: 224a47ff805f41738c1f78e160c6534e(会话id) <br/>RequestBody请求数据:<br/> FzW0t8uo9sWxEgj+CBXspDBk5A0EthEvjnFT1z5ecOa1oUmsNfUQhTa3hdVQYS0W <br/>ResponseBody: "tHgZ5ENlVhWq6QGmaaNRJy/DjU+1datQ2EiteFD9fAltwRR8EwX3gzROm1HwCa4hq8GOS+JMa64kcgrYzZ1WPRvqCw+Y6jEeOcgiNAxCAchN23Mv/dob0aeM4CwI5pzx1QGBsGJeTLle5Dv9oDkTyg=="</code>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 返回数据解密 | <code>// 响应后脚本 - 解密SM4加密的响应数据<br/>// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）<br/>var secretKey = "0123456789abcdeffedcba7896543210"; // 必须是16字节（128位）<br/>function decryptData(ciphertext, key, iv) {<br/>    // 使用SM4-CBC模式解密<br/>    let decryptStr = ciphertext.replaceAll("\"", "");<br/>    // 将Base64转换为字节数组<br/>    var ciphertextBytes = base64ToBytes(decryptStr);<br/>    // 将字节数组转换为16进制字符串<br/>    var ciphertextHex = bytesToHex(ciphertextBytes);<br/>    // 使用SM4-CBC模式加密<br/>    var decryptedResult = sm4.decrypt(ciphertextHex, key, { mode: 'cbc', iv: iv })<br/>    return decryptedResult;<br/>}<br/>// 辅助函数：Base64转字节数组<br/>function base64ToBytes(base64) {<br/>    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';<br/>    base64 = base64.replace(/=+$/, '');<br/>    var bytes = [];<br/>    for (var i = 0; i < base64.length; i += 4) {<br/>        var enc1 = base64Chars.indexOf(base64.charAt(i));<br/>        var enc2 = base64Chars.indexOf(base64.charAt(i + 1));<br/>        var enc3 = base64Chars.indexOf(base64.charAt(i + 2));<br/>        var enc4 = base64Chars.indexOf(base64.charAt(i + 3));<br/><br/>        var byte1 = (enc1 << 2) \| (enc2 >> 4);<br/>        var byte2 = ((enc2 & 0x0F) << 4) \| (enc3 >> 2);<br/>        var byte3 = ((enc3 & 0x03) << 6) \| enc4;<br/><br/>        bytes.push(byte1);<br/>        if (enc3 !== 64) bytes.push(byte2);<br/>        if (enc4 !== 64) bytes.push(byte3);<br/>    }<br/><br/>    return bytes;<br/>}<br/>// 辅助函数：字节数组转16进制字符串<br/>function bytesToHex(bytes) {<br/>    var hex = [];<br/>    for (var i = 0; i < bytes.length; i++) {<br/>        var b = bytes[i];<br/>        hex.push((b < 16 ? '0' : '') + b.toString(16));<br/>    }<br/>    return hex.join('');<br/>}<br/>// 获取响应数据<br/>var responseData = pm.response.text();<br/>const envIV = pm.response.headers.get('X-Encrypted-IV');<br/>// 解密数据<br/>var decryptedData = decryptData(responseData, secretKey, envIV);<br/>// 尝试解析为JSON（如果是JSON格式）<br/>try {<br/>    var jsonData = JSON.parse(decryptedData);<br/>    pm.response.json = function () { return jsonData; };<br/>} catch (e) {<br/>    // 如果不是JSON，保留原始解密文本<br/>    pm.response.text = function () { return decryptedData; };<br/>}<br/>// 记录解密结果到控制台<br/>console.log("解密响应:", decryptedData);</code> |

# 四、算法介绍

数据传输各模式对比

| 加密类型  | 模式        | 核心特点              | 优点            | 缺点               | 典型用途              |
|-------|-----------|-------------------|---------------|------------------|-------------------|
| 对称加密  | ECB（无 IV） | 块独立加密，无 IV        | 简单、效率高        | 密文块重复，安全性极差      | 已弃用，仅早期低安全场景      |
| 对称加密  | 固定 IV     | 用固定 IV 混合加密       | 实现简单，比 ECB 安全 | 明文开头重复时密文重复，安全性弱 | 内部低敏感、短周期传输       |
| 对称加密  | 动态 IV     | 随机 IV，随密文传输       | 安全性高，无密文重复    | 需传输 IV，依赖 IV 随机性 | HTTPS、敏感 API、文件加密 |
| 非对称混合 | 请求头密钥模式   | 单次请求独立生成对称密钥，公钥加密 | 安全高效，适合单次请求   | 每次请求有非对称加密开销     | 开放平台 API、一次性数据提交  |
| 非对称混合 | 会话模式      | 会话初期协商会话密钥，后续对称加密 | 效率极高，适合持续通信   | 会话密钥泄露影响整个会话     | 即时通讯、VPN、在线会议     |

## 非对称秘钥算法介绍

| **算法**     | **密钥长度范围**          | **推荐密钥长度**    | **安全强度（位）**   |
|------------|---------------------|---------------|---------------|
| RSA        | 1024-4096 位         | 2048 位        | 约 112 位       |
| DSA        | 1024-3072 位         | 2048 位        | 约 112 位       |
| ElGamal    | 1024-4096 位         | 2048 位        | 约 112 位       |
| ECDSA/ECDH | P-256, P-384, P-521 | P-256 (128 位) | 128/192/256 位 |
| SM2        | SM2-P-256           | 256 位         | 128 位         |



# 五、问题排查
+ Expected parsed RequestPath in request attribute "org.springframework.web.util.ServletRequestPathUtils.PATH".  
  修改路径解析的方式
``` yaml
spring:
  mvc:
    pathmatch:
      matching-strategy: ant_path_matcher

```