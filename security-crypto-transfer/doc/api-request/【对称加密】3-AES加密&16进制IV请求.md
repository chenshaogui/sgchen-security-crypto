AES加密&16进制IV请求
1. spring boot配置文件
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
  # 数据存储加解密配置
  database:
    enabled: true  # 默认开启，显式关闭数据库加密配置
    secretKey: "testtest12345678" # 算法配置秘钥
    algorithm: "AES_ECB_PKCS7"  # 对应SecretAlgorithm枚举，加解密算法
```


2. 客户端加密请求数据
```html
// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）
var secretKey = "0123456789abcdeffedcba9876543210"; // 必须是16字节（128位）
// 生成 16 字节随机 IV（以 WordArray 格式表示）
var iv = CryptoJS.lib.WordArray.random(16);
// 转换为 Base64 字符串（适合在 HTTP 请求头中传输）
var ivBase64 = iv.toString(CryptoJS.enc.Base64);
// 转换为十六进制字符串（可读性更好）
var ivHex = iv.toString(CryptoJS.enc.Hex);
// 请求前脚本 - SM4加密请求数据并以Base64格式输出
function encryptData(word, key, iv) {
    let srcs = CryptoJS.enc.Utf8.parse(typeof word === "string" ? word : JSON.stringify(word));
    let keyStr = CryptoJS.enc.Hex.parse(key);
    let ivstr = CryptoJS.enc.Hex.parse(iv);
    let encrypted = CryptoJS.AES.encrypt(srcs, keyStr, { iv: ivstr, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    console.log("加密字符串", encrypted.toString())
    return encrypted.toString();
}

// 辅助函数：16进制字符串转字节数组
function hexToBytes(hex) {
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}
// 辅助函数：字节数组转Base64
function bytesToBase64(bytes) {
    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var result = '';
    var i = 0;

    while (i < bytes.length) {
        var byte1 = bytes[i++];
        var byte2 = i < bytes.length ? bytes[i++] : 0;
        var byte3 = i < bytes.length ? bytes[i++] : 0;

        var enc1 = byte1 >> 2;
        var enc2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
        var enc3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6);
        var enc4 = byte3 & 0x3F;

        if (i > bytes.length + 1) {
            enc3 = enc4 = 64;
        } else if (i > bytes.length) {
            enc4 = 64;
        }

        result += base64Chars.charAt(enc1) + base64Chars.charAt(enc2) +
            base64Chars.charAt(enc3) + base64Chars.charAt(enc4);
    }

    return result;
}
// 获取请求数据
var requestData = pm.request.body.raw;
// ivHex = "0102030405060708"
var encryptedData = encryptData(requestData, secretKey, ivHex);
// 设置加密后的数据到请求体
pm.request.body.raw = encryptedData;
// 可选：添加加密信息头
pm.request.headers.upsert({
    key: 'X-Encrypted-IV',
    value: ivHex
});
```


3. 客户端解密数据
```html
// 响应后脚本 - 解密SM4加密的响应数据
// 设置你的密钥和IV（实际项目中应从配置或环境变量获取）
var secretKey = "0123456789abcdeffedcba9876543210"; // 必须是16字节（128位）
function decryptData(ciphertext, key, iv) {
    let decryptStr = ciphertext.replaceAll("\"", "");
    let keyStr = CryptoJS.enc.Hex.parse(key);
    let ivstr = CryptoJS.enc.Hex.parse(iv);
    var decryptedResult = CryptoJS.AES.decrypt(decryptStr, keyStr, { iv: ivstr, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    let decryptedStr = CryptoJS.enc.Utf8.stringify(decryptedResult);
    return decryptedStr.toString();
}

// 获取响应数据
var responseData = pm.response.text();
const envIV = pm.response.headers.get('X-Encrypted-IV');
// 解密数据
var decryptedData = decryptData(responseData, secretKey, envIV);
// 尝试解析为JSON（如果是JSON格式）
try {
    var jsonData = JSON.parse(decryptedData);
    pm.response.json = function () { return jsonData; };
} catch (e) {
    // 如果不是JSON，保留原始解密文本
    pm.response.text = function () { return decryptedData; };
}

// 记录解密结果到控制台
console.log("解密响应:", decryptedData);
```
