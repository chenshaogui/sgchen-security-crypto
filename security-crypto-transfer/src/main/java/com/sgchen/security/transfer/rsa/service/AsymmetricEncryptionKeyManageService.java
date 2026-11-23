package com.sgchen.security.transfer.rsa.service;

import cn.hutool.extra.spring.SpringUtil;
import com.alibaba.fastjson2.JSONObject;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.constant.SecurityConstants;
import com.sgchen.security.core.util.CryptoAsymmetricUtil;
import com.sgchen.security.transfer.rsa.bean.RsaKeyPairEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 密钥管理服务实现
 */
@ConditionalOnExpression("${csg-security.request.enabled:true} " +
        "&& T(org.springframework.util.StringUtils).hasText('${csg-security.request.useAsymmetricMode:}') " +
        "&& T(org.springframework.util.StringUtils).hasText('${csg-security.request.clientCode:}')"
)
@Component
public class AsymmetricEncryptionKeyManageService implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(AsymmetricEncryptionKeyManageService.class);

    /**
     * RSA密钥有效期(小时)
     */
    @Value("${" + SecurityConstants.RSA_REDIS_PREFIX + ".rsa-key.expiryHours:24}")
    private int keyExpiryHours;

    /**
     * 事务锁配置
     */
    // 统一锁的前缀
    private static final String LOCK_KEY_PREFIX = SecurityConstants.RSA_REDIS_PREFIX + ".rsa-key:lock:";
    // 通用锁，用于生成新密钥对、刷新公钥和清除过期密钥
    private static final String GENERAL_LOCK_KEY = "general_key_operation";
    // 默认锁超时时间
    private static final long DEFAULT_LOCK_TIMEOUT = 30; // 默认锁超时时间（秒）

    /**
     * 密钥对缓存
     */
    // redis保存密钥对
    private static final String RSA_KEY_PAIR_PREFIX = SecurityConstants.RSA_REDIS_PREFIX + ".rsa-key:keypair:";
    // redis保存的密钥对最新版本
    private static final String LATEST_KEY_VERSION = SecurityConstants.RSA_REDIS_PREFIX + ".rsa-key:latest:version";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Override
    public void afterPropertiesSet() {
        // 启动定时任务
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

        // 启动定时任务，每天生成新密钥对（提前生成）
        executor.scheduleAtFixedRate(() -> {
            try {
                cleanupExpiredKeys();

                RsaKeyPairEntity latestKey = getLatestKeyPair();
                // 如果当前密钥将在2小时内过期，生成新密钥
                if (latestKey != null && latestKey.getExpireTime() < System.currentTimeMillis() + 2 * 60 * 60 * 1000) {
                    generateAndStoreNewKeyPair();
                }
            } catch (Exception e) {
                logger.error("生成新密钥对（提前生成）任务执行失败", e);
            }
        }, keyExpiryHours, keyExpiryHours, TimeUnit.HOURS);
    }

    /**
     * 本地缓存RSA密钥对：减少Redis访问
     */
    private final LoadingCache<String, RsaKeyPairEntity> localCache = Caffeine.newBuilder()
            .maximumSize(10) //限制缓存能容纳的最大条目数（key-value 对的数量），超出时自动驱逐最不常用的条目‌
            .expireAfter(new Expiry<String, RsaKeyPairEntity>() {
                @Override
                public long expireAfterCreate(String key, RsaKeyPairEntity value, long currentTime) {
                    // 计算公钥剩余有效期（毫秒）
                    long remainingTimeMillis = value.getExpireTime() - System.currentTimeMillis();

                    // 计算缓存时间（毫秒）：取剩余时间的1/3，最小10分钟，最大2小时
                    long cacheTimeMillis = Math.min(
                            2 * 60 * 60 * 1000L,  // 最大2小时
                            Math.max(
                                    remainingTimeMillis / 3,
                                    10 * 60 * 1000L  // 最小10分钟
                            )
                    );

                    // 关键修正：将毫秒转换为纳秒
                    return TimeUnit.MILLISECONDS.toNanos(cacheTimeMillis);
                }

                @Override
                public long expireAfterUpdate(String key, RsaKeyPairEntity value, long currentTime, long currentDuration) {
                    // 更新时沿用创建时的过期时间
                    return currentDuration;
                }

                @Override
                public long expireAfterRead(String key, RsaKeyPairEntity value, long currentTime, long currentDuration) {
                    // 读取时不改变过期时间
                    return currentDuration;
                }
            }) // 设定条目‌写入缓存后的存活时间‌，超时自动删除‌
            .recordStats() // 启用统计
            .build(new CacheLoader<String, RsaKeyPairEntity>() {
                @Override
                public RsaKeyPairEntity load(String keyVersion) {
                    // 缓存未命中时，从Redis加载
                    String clientId = getClientId();
                    String cacheData = redisTemplate.opsForValue().get(RSA_KEY_PAIR_PREFIX + clientId + ":" + keyVersion);
                    return JSONObject.parseObject(cacheData, RsaKeyPairEntity.class);
                }
            });

    /**
     * 获取当前RSA公钥（高并发安全） 只能通过接口获取
     *
     * @return RsaKeyPairEntity
     */
    public RsaKeyPairEntity getOrRefreshCurrentRsaPairKey() {
        // 1. 先从本地缓存获取
        RsaKeyPairEntity pairEntity = getLatestKeyPair();

        // 2. 检查公钥
        if (pairEntity != null) {
            return pairEntity;
        }

        // 3. 公钥不存在或即将过期，进入双重检查锁逻辑
        return generateAndStoreNewKeyPair();
    }

    public RsaKeyPairEntity getOrRefreshCurrentRsaPairKey(String version) {
        // 1. 先从本地缓存获取
        RsaKeyPairEntity pairEntity = getKeyPairByVersion(version);

        // 2. 检查公钥
        if (pairEntity != null) {
            return pairEntity;
        }

        // 3. 公钥不存在或即将过期，进入双重检查锁逻辑
        return generateAndStoreNewKeyPair();
    }

    /**
     * 尝试获取锁（原子操作）
     *
     * @return lockId
     */
    private String acquireLock(String key, long timeout, TimeUnit unit) {
        String clientId = getClientId();
        String lockKey = LOCK_KEY_PREFIX + clientId + ":" + key;
        String requestId = getUUID();

        // 使用SETNX命令获取锁，并设置过期时间防止死锁
        Boolean result = redisTemplate.opsForValue().setIfAbsent(
                lockKey, requestId, timeout, unit
        );

        return result != null && result ? requestId : null;
    }

    /**
     * 释放锁（使用Lua脚本保证原子性）
     */
    private void releaseLock(String key, String requestId) {
        String clientId = getClientId();
        String lockKey = LOCK_KEY_PREFIX + clientId + ":" + key;
        try {
            // 使用Lua脚本确保原子性：先检查锁的持有者，再删除锁
            Long result = redisTemplate.execute(
                    RELEASE_LOCK_SCRIPT,
                    Collections.singletonList(lockKey),
                    requestId
            );
            if (result == 0L) {
                logger.error("释放锁失败，key: {}, requestId: {}", lockKey, requestId);
            }
        } catch (Exception e) {
            logger.error("释放锁时发生异常，key: {}, requestId: {}", lockKey, requestId, e);
        }
    }

    /**
     * 生成新公钥并存储到Redis
     *
     * @return RsaKeyPairEntity
     */
    public RsaKeyPairEntity generateAndStoreNewKeyPair() {
        String lockId = null;
        String clientId = getClientId();

        try {
            lockId = acquireLock(GENERAL_LOCK_KEY, DEFAULT_LOCK_TIMEOUT, TimeUnit.SECONDS);

            if (lockId == null) {
                throw new SecurityException("获取密钥生成锁失败，请稍后重试");
            }

            RsaKeyPairEntity latestKey = getLatestKeyPair();
            if (latestKey != null && latestKey.getExpireTime() > System.currentTimeMillis()) {
                return latestKey;
            }

            SecretContext secretConfig = SpringUtil.getBean(SecretContext.class);
            if (secretConfig == null) {
                throw new SecurityException("加密未配置");
            }
            if (secretConfig.getRequestAsymmetricMode() == null) {
                throw new SecurityException("非对称加密模式未配置");
            }
            KeyPair keyPair = CryptoAsymmetricUtil.generateAsymmetricKeyPair(secretConfig.getRequestAsymmetricMode());

            String publicKeyStr = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKeyStr = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            String version = getUUID();
            RsaKeyPairEntity keyPairEntity = new RsaKeyPairEntity();
            keyPairEntity.setVersion(version);
            keyPairEntity.setPublicKey(publicKeyStr);
            keyPairEntity.setPrivateKey(privateKeyStr);
            keyPairEntity.setExpireTime(System.currentTimeMillis() + keyExpiryHours * 60 * 60 * 1000L);

            String key = RSA_KEY_PAIR_PREFIX + clientId + ":" + version;
            redisTemplate.opsForValue().set(
                    key,
                    JSONObject.toJSONString(keyPairEntity),
                    keyExpiryHours + 1L,
                    TimeUnit.HOURS
            );

            redisTemplate.opsForValue().set(LATEST_KEY_VERSION + ":" + clientId, version);

            // 更新本地缓存
            localCache.put(version, keyPairEntity);

            return keyPairEntity;
        } finally {
            if (lockId != null) {
                releaseLock(GENERAL_LOCK_KEY, lockId);
            }
        }
    }

    /**
     * 获取最新的RSA密钥对。非接口获取，其他内部调用时通过该方法
     *
     * @return 非对称密钥对
     */
    public RsaKeyPairEntity getLatestKeyPair() {
        String clientId = getClientId();
        String version = redisTemplate.opsForValue().get(LATEST_KEY_VERSION + ":" + clientId);
        return version != null ? getKeyPairByVersion(version) : null;
    }

    /**
     * 根据版本获取RSA密钥对（优先从本地缓存获取）
     *
     * @param version uuid生成的版本
     * @return 非对称密钥对
     */
    public RsaKeyPairEntity getKeyPairByVersion(String version) {
        if (version == null) {
            return null;
        }
        return localCache.get(version);
    }

    /**
     * 获取缓存统计信息
     *
     * @return str
     */
    public String getCacheStats() {
        return localCache.stats().toString();
    }

    /**
     * 清除过期的key
     */
    private void cleanupExpiredKeys() {
        String lockId = null;
        String clientId = getClientId();

        try {
            lockId = acquireLock(GENERAL_LOCK_KEY, 60, TimeUnit.SECONDS);

            if (lockId == null) {
                return;
            }

            long now = System.currentTimeMillis();
            String latestVersion = redisTemplate.opsForValue().get(LATEST_KEY_VERSION + ":" + clientId);

            Set<String> allKeys = redisTemplate.keys(RSA_KEY_PAIR_PREFIX + clientId + ":*");
            for (String key : allKeys) {
                String version = key.substring((RSA_KEY_PAIR_PREFIX + clientId + ":").length());

                if (!version.equals(latestVersion)) {
                    String cacheData = redisTemplate.opsForValue().get(key);
                    RsaKeyPairEntity keyPair = JSONObject.parseObject(cacheData, RsaKeyPairEntity.class);

                    if (keyPair != null && keyPair.getExpireTime() < now) {
                        redisTemplate.delete(key);
                        localCache.invalidate(version); // 从本地缓存中移除
                    }
                }
            }
        } finally {
            if (lockId != null) {
                releaseLock(GENERAL_LOCK_KEY, lockId);
            }
        }
    }

    // 释放锁的Lua脚本（确保原子性）
    private static final RedisScript<Long> RELEASE_LOCK_SCRIPT = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then\n" +
                    "    return redis.call('del', KEYS[1])\n" +
                    "else\n" +
                    "    return 0\n" +
                    "end",
            Long.class
    );

    private String getUUID() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private String getClientId() {
        SecretContext secretConfig = SpringUtil.getBean(SecretContext.class);
        String clientId = secretConfig != null ? secretConfig.getClientCode() : "default";
        return clientId != null ? clientId : "default";
    }
}