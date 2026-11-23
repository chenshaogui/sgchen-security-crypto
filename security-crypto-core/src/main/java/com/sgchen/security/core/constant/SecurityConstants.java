package com.sgchen.security.core.constant;

public class SecurityConstants {

    private SecurityConstants(){}

    /**
     * feign调用时头部信息
     */
    public static final String FEIGN_CLIENT_CALL = "Feign-Client-Call";

    /**
     * 请求和响应数据IV头部信息
     */
    public static final String X_ENC_IV = "X-Encrypted-IV";

    /**
     * 请求和响应数据客户端密钥key
     */
    public static final String X_ENC_CLIENT_KEY = "X-Encrypted-ClientKey";

    /**
     * 请求响应数据SessionId
     */
    public static final String X_ENC_SESSION_ID = "X-Encrypted-SessionId";

    /**
     * 非对称密钥redis缓存前缀
     */
    public static final String RSA_REDIS_PREFIX = "csg-tsc";

}
