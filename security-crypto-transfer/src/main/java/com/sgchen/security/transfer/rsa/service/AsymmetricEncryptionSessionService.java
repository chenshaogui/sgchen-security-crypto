package com.sgchen.security.transfer.rsa.service;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.extra.spring.SpringUtil;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.constant.SecurityConstants;
import com.sgchen.security.core.exception.AuthSecurityException;
import com.sgchen.security.core.util.CryptoAsymmetricUtil;
import com.sgchen.security.transfer.rsa.bean.EncryptionSessionInfo;
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

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.TimeUnit;

@ConditionalOnExpression("${csg-security.request.enabled:true} " +
        "&& T(org.springframework.util.StringUtils).hasText('${csg-security.request.useAsymmetricMode:}') " +
        "&& T(org.springframework.util.StringUtils).hasText('${csg-security.request.clientCode:}')"
)
@Component
public class AsymmetricEncryptionSessionService implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(AsymmetricEncryptionSessionService.class);

    /**
     * 存储会话信息的有序集合（Sorted Set）的键名
     */
    private static final String SESSIONS_ZSET_KEY = SecurityConstants.RSA_REDIS_PREFIX + ".rsa-session.sessions";
    /**
     * sessionId在redis缓存中的前缀
     */
    private static final String SESSION_ID_PREFIX = SecurityConstants.RSA_REDIS_PREFIX + ".rsa-session.sid:";
    /**
     * 增加ip访问限制，防止缓存key太多问题
     */
    private static final String IP_RATE_LIMIT_KEY_PREFIX = SecurityConstants.RSA_REDIS_PREFIX + ".rsa-session.ip_rate:";
    /**
     * 创建session时分布式锁前缀
     */
    private static final String LOCK_KEY_PREFIX = SecurityConstants.RSA_REDIS_PREFIX + ".rsa-session.session_lock:";

    /**
     * 客户端IP在会话哈希表中的字段名
     */
    private static final String CLIENT_IP_FIELD = "clientIp";

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private AsymmetricEncryptionKeyManageService keyService;

    /**
     * 最大会话数
     */
    @Value("${" + SecurityConstants.RSA_REDIS_PREFIX + ".rsa-session.maxCount:100000}")
    private long maxSessionCount;

    /**
     * 会话过期时间，单位秒，默认8小时过期
     */
    @Value("${" + SecurityConstants.RSA_REDIS_PREFIX + ".rsa-session.expirySeconds:28800}")
    private long sessionExpirySeconds;

    /**
     * 每个IP每分钟最多允许1000次请求
     */
    // 增加ip访问数量，防止缓存key过多
    @Value("${" + SecurityConstants.RSA_REDIS_PREFIX + ".rsa-session.ipRateLimit:1000}")
    private long ipRateLimit;

    // 如果设置为 60 秒，表示统计最近 60 秒内的请求次数
    @Value("${" + SecurityConstants.RSA_REDIS_PREFIX + ".rsa-session.ipRateWindow:60}")
    private long ipRateWindowSeconds;

    public EncryptionSessionInfo createEncryptedSession(String clientIp, String encryptedClientKey) {
        if (clientIp == null) {
            throw new IllegalArgumentException("Client IP cannot be null");
        }
        String clientId = getClientId();
        String lockKey = LOCK_KEY_PREFIX + clientId + ":" + clientIp;
        boolean isLocked = false;
        try {
            isLocked = acquireLock(lockKey);
            if (!isLocked) {
                throw new SecurityException("无法获取锁，请稍后再试");
            }
            if (!checkIpRateLimit(clientIp)) {
                throw new SecurityException("请求频率过高，请稍后再试");
            }

            String clientKey = decryptClientKey(encryptedClientKey);

            String clientKeyHash = calculateHash(clientKey);

            // 检查是否存在相同 IP 和密钥哈希的有效会话
            EncryptionSessionInfo existingSession = findExistingSession(clientIp, clientKeyHash);
            if (existingSession != null) {
                // 检查非对称密钥是否过期
                if (isKeyExpired(existingSession.getPublicKeyVersion())) {
                    // 密钥过期，删除旧会话
                    deleteSession(existingSession.getSessionId());
                    existingSession = null;
                } else {
                    // 刷新会话过期时间
                    refreshSession(existingSession.getSessionId());
                    return existingSession;
                }
            }

            String sessionId = getUUID(); // 仅使用 UUID 作为 sessionId
            String prefixedSessionId = getPrefixedSessionId(sessionId, clientId); // 添加前缀用于 Redis 存储
            long now = System.currentTimeMillis();
            long expireTime = now + sessionExpirySeconds * 1000;

            // 清理过期会话
            cleanupExpiredSessions(clientId);

            RsaKeyPairEntity latestKeyPair = keyService.getLatestKeyPair();
            if (latestKeyPair == null) {
                throw new AuthSecurityException("公钥已过期");
            }
            // 执行原子操作：清理过期会话 + 创建新会话
            Boolean result = redisTemplate.execute(
                    createSessionScript,
                    Collections.singletonList(SESSIONS_ZSET_KEY + ":" + clientId),
                    prefixedSessionId,             // ARGV[1]: 会话ID（添加前缀）
                    String.valueOf(now),      // ARGV[2]: 当前时间戳(毫秒)
                    String.valueOf(sessionExpirySeconds), // ARGV[3]: 会话有效期(秒)
                    String.valueOf(maxSessionCount),      // ARGV[4]: 最大会话数
                    clientKey,                // ARGV[5]: 客户端密钥
                    latestKeyPair.getVersion(), // ARGV[6]: 公钥版本
                    String.valueOf(expireTime),    // ARGV[7]: 过期时间戳(毫秒)
                    clientIp                       // ARGV[8]: 客户端IP
            );

            if (Boolean.FALSE.equals(result)) {
                throw new SecurityException("会话数量已达到上限");
            }

            // 返回会话信息
            EncryptionSessionInfo sessionInfo = new EncryptionSessionInfo();
            sessionInfo.setSessionId(sessionId); // 仅返回 UUID 作为 sessionId
            sessionInfo.setClientKey(clientKey);
            sessionInfo.setCreateTime(now);
            sessionInfo.setExpireTime(expireTime);
            sessionInfo.setPublicKeyVersion(latestKeyPair.getVersion());

            return sessionInfo;
        } finally {
            if (isLocked) {
                releaseLock(lockKey);
            }
        }
    }

    private boolean acquireLock(String lockKey) {
        if (redisTemplate == null) {
            throw new IllegalStateException("RedisTemplate is not initialized");
        }
        if (lockKey == null) {
            throw new IllegalArgumentException("Lock key cannot be null");
        }
        return Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(lockKey, "locked", 10, TimeUnit.SECONDS));
    }

    private void releaseLock(String lockKey) {
        if (redisTemplate == null) {
            throw new IllegalStateException("RedisTemplate is not initialized");
        }
        if (lockKey == null) {
            throw new IllegalArgumentException("Lock key cannot be null");
        }
        redisTemplate.delete(lockKey);
    }

    private String decryptClientKey(String encryptedClientKey) {
        RsaKeyPairEntity latestKeyPair = keyService.getLatestKeyPair();
        if (latestKeyPair == null) {
            throw new AuthSecurityException("公钥已过期");
        }
        SecretContext secretConfig = SpringUtil.getBean(SecretContext.class);
        if (secretConfig == null) {
            throw new SecurityException("加密未配置");
        }
        if (secretConfig.getRequestAsymmetricMode() == null) {
            throw new SecurityException("非对称加密模式未配置");
        }
        String privateKeyStr = latestKeyPair.getPrivateKey();
        PrivateKey privateKey = CryptoAsymmetricUtil.restorePrivateKey(privateKeyStr, secretConfig.getRequestAsymmetricMode());

        return CryptoAsymmetricUtil.decryptWithPrivateKey(encryptedClientKey, privateKey, secretConfig.getRequestAsymmetricMode());
    }

    // 验证会话有效性
    public boolean isValidSession(String sessionId) {
        String clientId = getClientId();
        String prefixedSessionId = getPrefixedSessionId(sessionId, clientId); // 添加前缀用于 Redis 查询
        // 检查会话是否存在且未过期
        Double score = redisTemplate.opsForZSet().score(SESSIONS_ZSET_KEY + ":" + clientId, prefixedSessionId);
        return score != null && score > System.currentTimeMillis();
    }

    public EncryptionSessionInfo getSessionInfo(String sessionId) {
        String clientId = getClientId();
        String prefixedSessionId = getPrefixedSessionId(sessionId, clientId); // 添加前缀用于 Redis 查询
        Map<Object, Object> hash = redisTemplate.opsForHash().entries(prefixedSessionId);
        if (hash.isEmpty()) {
            throw new SecurityException("Failed to query SessionInfo from sessionId");
        }
        EncryptionSessionInfo info = new EncryptionSessionInfo();
        try {
            // 将Map中的属性复制到对象
            BeanUtil.copyProperties(hash, info);
            info.setSessionId(sessionId); // 仅返回 UUID 作为 sessionId
            return info;
        } catch (Exception e) {
            throw new SecurityException("Failed to populate SessionInfo from map", e);
        }
    }

    public void refreshSession(String sessionId) {
        String clientId = getClientId();
        String prefixedSessionId = getPrefixedSessionId(sessionId, clientId); // 添加前缀用于 Redis 操作
        long expireTime = System.currentTimeMillis() + sessionExpirySeconds * 1000;
        redisTemplate.opsForZSet().add(SESSIONS_ZSET_KEY + ":" + clientId, prefixedSessionId, expireTime);

        EncryptionSessionInfo sessionInfo = getSessionInfo(sessionId);
        if (sessionInfo != null) {
            sessionInfo.setExpireTime(expireTime);
            redisTemplate.opsForHash().put(prefixedSessionId, "expireTime", String.valueOf(expireTime));
        }
    }

    public void deleteSession(String sessionId) {
        String clientId = getClientId();
        String prefixedSessionId = getPrefixedSessionId(sessionId, clientId); // 添加前缀用于 Redis 操作
        redisTemplate.opsForZSet().remove(SESSIONS_ZSET_KEY + ":" + clientId, prefixedSessionId);
        redisTemplate.delete(prefixedSessionId);
    }

    public void deleteAllSessions() {
        String clientId = getClientId();
        // 删除有序集合
        redisTemplate.delete(SESSIONS_ZSET_KEY + ":" + clientId);
        // 删除所有会话的哈希表
        Set<String> sessionIds = redisTemplate.opsForZSet().range(SESSIONS_ZSET_KEY + ":" + clientId, 0, -1);
        if (sessionIds != null) {
            for (String sessionId : sessionIds) {
                redisTemplate.delete(sessionId);
            }
        }
    }

    public long getSessionCount() {
        String clientId = getClientId();
        Long count = redisTemplate.opsForZSet().zCard(SESSIONS_ZSET_KEY + ":" + clientId);
        return count != null ? count : 0;
    }

    // 清理过期会话
    private long cleanupExpiredSessions(String clientId) {
        long now = System.currentTimeMillis();

        // 先检查集合是否存在
        Boolean exists = redisTemplate.hasKey(SESSIONS_ZSET_KEY + ":" + clientId);
        if (!exists) {
            return 0;
        }

        // 获取过期的会话ID
        Set<String> expiredSessions = redisTemplate.opsForZSet().rangeByScore(
                SESSIONS_ZSET_KEY + ":" + clientId, 0, now
        );

        // 删除对应的会话信息
        if (expiredSessions != null && !expiredSessions.isEmpty()) {
            for (String sessionId : expiredSessions) {
                redisTemplate.delete(sessionId);
            }
        }

        // 执行删除并安全处理返回值
        Long removedCount = redisTemplate.opsForZSet().removeRangeByScore(SESSIONS_ZSET_KEY + ":" + clientId, 0, now);
        return removedCount != null ? removedCount : 0;
    }

    private boolean checkIpRateLimit(String clientIp) {
        String clientId = getClientId();
        String key = IP_RATE_LIMIT_KEY_PREFIX + clientId + ":" + clientIp;
        long now = System.currentTimeMillis();

        // 直接返回是否允许访问
        Boolean allowed = redisTemplate.execute(
                rateLimitScript,
                Collections.singletonList(key),
                String.valueOf(now),
                String.valueOf(ipRateWindowSeconds * 1000),
                String.valueOf(ipRateLimit)
        );

        return Boolean.TRUE.equals(allowed);
    }

    // 创建会话的Lua脚本（优化版本）
    private static final RedisScript<Boolean> createSessionScript = new DefaultRedisScript<>(
            // 1. 初始化会话集合（如果不存在）
            "if not redis.call('EXISTS', KEYS[1]) then\n" +
                    "  redis.call('ZADD', KEYS[1], 0, 'dummy')\n" +
                    "  redis.call('ZREM', KEYS[1], 'dummy')\n" +
                    "end\n" +

                    // 2. 计算当前时间和过期阈值
                    "local now = tonumber(ARGV[2])\n" +
                    "local expireThreshold = now - (tonumber(ARGV[3]) * 1000)\n" +

                    // 3. 清理真正的过期会话（使用 expireTime - 会话有效期 作为阈值）
                    "local expiredIds = redis.call('ZRANGEBYSCORE', KEYS[1], 0, expireThreshold)\n" +
                    "if tonumber(#expiredIds) > 0 then\n" +
                    "  redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, expireThreshold)\n" +
                    " for i, expiredId in ipairs(expiredIds) do\n" +
                    "  redis.call('DEL', expiredId)\n" +
                    " end\n" +
                    "end\n" +

                    // 4. 检查会话数量是否超过上限
                    "local count = redis.call('ZCARD', KEYS[1])\n" +
                    "if tonumber(count) >= tonumber(ARGV[4]) then\n" +
                    "  return false\n" +
                    "end\n" +

                    // 5. 创建新会话（使用 expireTime 作为分数）
                    "local expireTime = tonumber(ARGV[7])\n" +
                    "redis.call('ZADD', KEYS[1], expireTime, ARGV[1])\n" +

                    // 6. 存储会话详细信息到单独的哈希表
                    "redis.call('HSET', ARGV[1], 'clientKey', ARGV[5])\n" +
                    "redis.call('HSET', ARGV[1], 'publicKeyVersion', ARGV[6])\n" +
                    "redis.call('HSET', ARGV[1], 'createTime', ARGV[2])\n" +
                    "redis.call('HSET', ARGV[1], 'expireTime', ARGV[7])\n" +
                    "redis.call('HSET', ARGV[1], 'clientIp', ARGV[8])\n" +

                    // 7. 设置会话哈希表的过期时间（秒）
                    "redis.call('EXPIRE', ARGV[1], tonumber(ARGV[3]))\n" +

                    // 8. 返回成功标识
                    "return true",
            Boolean.class
    );

    // IP限流的Lua脚本（优化版本：直接在脚本内判断是否超出阈值）
    private static final RedisScript<Boolean> rateLimitScript = new DefaultRedisScript<>(
            // 如果键不存在，创建有序集合
            "if not redis.call('EXISTS', KEYS[1]) then\n" +
                    "  redis.call('ZADD', KEYS[1], 0, 0)\n" +
                    "end\n" +

                    // 移除窗口外的请求记录
                    "redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1] - ARGV[2])\n" +

                    // 获取当前计数
                    "local count = redis.call('ZCARD', KEYS[1])\n" +

                    // 如果已超过阈值，直接返回
                    "if count >= tonumber(ARGV[3]) then\n" +
                    "  return false\n" +
                    "end\n" +

                    // 未超过阈值，添加当前请求记录
                    "redis.call('ZADD', KEYS[1], ARGV[1], ARGV[1])\n" +

                    // 设置过期时间
                    "redis.call('EXPIRE', KEYS[1], ARGV[2] / 1000)\n" +

                    // 返回允许访问
                    "return true",
            Boolean.class
    );

    // 查找会话的Lua脚本（优化版：返回候选会话及密钥，在Java层进行哈希比较）
    private static final RedisScript<List> findSessionScript = new DefaultRedisScript<>(
            "local activeSessions = redis.call('ZRANGEBYSCORE', KEYS[1], ARGV[1], '+inf')\n" +
                    "local matchedSession = nil\n" +
                    "local clientKey = nil\n" +
                    "\n" +
                    "for i, sessionId in ipairs(activeSessions) do\n" +
                    "  local storedIp = redis.call('HGET', sessionId, ARGV[2])\n" +
                    "  if storedIp == ARGV[3] then\n" +
                    "    clientKey = redis.call('HGET', sessionId, ARGV[4])\n" +
                    "    if clientKey ~= nil then\n" +
                    "      matchedSession = sessionId\n" +
                    "      break\n" +
                    "    end\n" +
                    "  end\n" +
                    "end\n" +
                    "\n" +
                    "return {matchedSession, clientKey}",
            List.class // 明确指定返回类型为List
    );

    private String getUUID() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 计算客户端密钥的哈希值
     */
    private String calculateHash(String clientKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(clientKey.getBytes("UTF-8"));

            StringBuilder hexString = new StringBuilder(2 * hashBytes.length);
            for (byte b : hashBytes) {
                String hex = String.format("%02x", b);
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("计算哈希值失败", e);
        }
    }

    /**
     * 查找相同 IP 和客户端密钥哈希的有效会话
     */
    private EncryptionSessionInfo findExistingSession(String clientIp, String clientKeyHash) {
        String clientId = getClientId();
        // 使用 Lua 脚本在 Redis 端批量处理会话查找
        List results = redisTemplate.execute(
                findSessionScript,
                Collections.singletonList(SESSIONS_ZSET_KEY + ":" + clientId),
                String.valueOf(System.currentTimeMillis()), // ARGV[1]: 当前时间戳
                CLIENT_IP_FIELD,                           // ARGV[2]: IP字段名
                clientIp,                                  // ARGV[3]: 目标IP
                "clientKey"                                // ARGV[4]: 密钥字段名
        );

        if (results == null || results.isEmpty() || results.get(0) == null) {
            return null;
        }

        String matchedSessionId = (String) results.get(0);
        String storedClientKey = (String) results.get(1);

        // 比较客户端密钥的哈希值，而非明文
        if (!clientKeyHash.equals(calculateHash(storedClientKey))) {
            return null;
        }

        // 从完整的 Redis key 中提取实际的 sessionId
        String sessionId = matchedSessionId.substring((SESSION_ID_PREFIX + clientId + ":").length());

        try {
            return getSessionInfo(sessionId);
        } catch (Exception e) {
            log.warn("获取会话信息失败: {}", sessionId, e);
            return null;
        }
    }

    /**
     * 检查非对称密钥是否过期
     */
    private boolean isKeyExpired(String keyVersion) {
        // 这里假设 EncryptionKeyManageService 有一个方法来检查密钥是否过期
        return keyService.getKeyPairByVersion(keyVersion) == null;
    }

    /**
     * 获取带前缀的 sessionId
     */
    private String getPrefixedSessionId(String sessionId, String clientId) {
        return SESSION_ID_PREFIX + clientId + ":" + sessionId;
    }

    @Override
    public void afterPropertiesSet() {
        // to do nothing
    }

    private String getClientId() {
        SecretContext secretConfig = SpringUtil.getBean(SecretContext.class);
        String clientId = secretConfig != null ? secretConfig.getClientCode() : "default";
        return clientId != null ? clientId : "default";
    }
}