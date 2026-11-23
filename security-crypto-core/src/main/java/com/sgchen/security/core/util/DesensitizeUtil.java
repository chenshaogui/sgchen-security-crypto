package com.sgchen.security.core.util;

import cn.hutool.core.util.DesensitizedUtil;
import com.sgchen.security.core.enums.DesensitizedMode;

/**
 * 脱敏的工具类
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
public class DesensitizeUtil {

    private DesensitizeUtil() {
    }


    /**
     * 通过模式脱敏
     *
     * @param desensitizedMode 脱敏模式
     * @param paramValue       原始值
     * @return str
     */
    public static String desensitizedByMode(DesensitizedMode desensitizedMode, String paramValue) {
        switch (desensitizedMode) {
            case password:
                return DesensitizedUtil.password(paramValue);
            case name:
                return DesensitizedUtil.chineseName(paramValue);
            case mobile:
                return DesensitizedUtil.mobilePhone(paramValue);
            case fixTel:
                return DesensitizedUtil.fixedPhone(paramValue);
            case idCard:
                return DesensitizedUtil.idCardNum(paramValue, 0, 4);
            case bankCard:
                return DesensitizedUtil.bankCard(paramValue);
            case email:
                return DesensitizedUtil.email(paramValue);
            case address:
                return DesensitizedUtil.address(paramValue, 8);
            case ipv4:
                return DesensitizedUtil.ipv4(paramValue);
            case ipv6:
                return DesensitizedUtil.ipv6(paramValue);
            default:
                return paramValue;
        }

    }


    /**
     * 脱敏
     *
     * @param value 原始值
     * @param front 头部位置
     * @param tail  尾部位置
     * @return str
     */
    public static String desensitized(String value, int front, int tail) {
        if ((front + tail) > value.length()) {
            return value;
        } else {
            int end = value.length() - tail;
            int hide = value.length() - front - tail;
            StringBuilder replaceStart = new StringBuilder();
            for (int i = 0; i < hide; i++) {
                replaceStart.append("*");
            }
            return value.substring(0, front) + replaceStart + value.substring(end);
        }
    }

}
