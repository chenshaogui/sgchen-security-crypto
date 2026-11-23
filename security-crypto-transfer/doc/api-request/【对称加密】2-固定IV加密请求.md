【对称加密】固定IV加密
1. spring boot配置文件
```yaml
csg-security:
  # 请求传输时加解密配置
  request:
    # 配置秘钥[使用useAsymmetricMode非对称模式时，可不配置]
    secretKey: "0123456789abcdeffedcba9876543210"
    # 配置IV[使用useAsymmetricMode非对称模式时，可不配置]
    secretIV: "0102030405060708"
    # 对应SecretAlgorithm枚举，加解密算法
    # 跳过错误模式：AES_ECB_PKCS5、AES_ECB_PKCS7、AES_CBC_PKCS7、SM4_ECB_PKCS7、SM4_CBC_PKCS7
    # 严格模式：AES_ECB_PKCS5_STRICT、AES_ECB_PKCS7_STRICT、AES_CBC_PKCS7_STRICT、SM4_ECB_PKCS7_STRICT、SM4_CBC_PKCS7_STRICT
    # 自定义其他算法：CUSTOM_ALGORITHM，启用自定义时必须配置 csg-security.request.customAlgorithm
    algorithm: "AES_CBC_PKCS7"
  # 数据存储加解密配置
  database:
    enabled: true  # 默认开启，显式关闭数据库加密配置
    secretKey: "testtest12345678" # 算法配置秘钥
    algorithm: "AES_ECB_PKCS7"  # 对应SecretAlgorithm枚举，加解密算法
```


2. 客户端加密请求数据
```html
let key = "0123456789abcdeffedcba9876543210";
const iv = CryptoJS.enc.Utf8.parse('0102030405060708');   //十六位十六进制数作为密钥偏移量
//加密方法
function Encrypt(word) {
    let srcs = CryptoJS.enc.Utf8.parse(typeof word === "string" ? word : JSON.stringify(word));
    key = CryptoJS.enc.Hex.parse(key);
    let encrypted = CryptoJS.AES.encrypt(srcs, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return encrypted.toString();
}
let requests = Encrypt(request.request_bodys);
pm.request.body.raw = requests;
```


3. 客户端解密数据
```html
let key = "0123456789abcdeffedcba9876543210";
const iv = CryptoJS.enc.Utf8.parse('0102030405060708');
//解密方法
function Decrypt(word) {
    key = CryptoJS.enc.Hex.parse(key);
    let decrypt = CryptoJS.AES.decrypt(word.replaceAll("\"", ""), key, { mode: CryptoJS.mode.CBC,iv:iv,padding: CryptoJS.pad.Pkcs7 });
    let decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
    return decryptedStr.toString();
}
let responses = Decrypt(response.raw.responseText);
console.log(JSON.parse(responses))
pm.response.setBody(responses);
```
