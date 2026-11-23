package com.sgchen.security.core.enums;


/**
 * 脱敏定义的模版，可以根据需要添加或删除
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
public enum DesensitizedMode {

    password("密码", 0, 0),

    name("姓名", 1, 0),

    mobile("手机号码", 3, 4),

    fixTel("固定电话", 4, 2),

    idCard("身份证号码", 1, 2),

    bankCard("银行卡号", 0, 4),

    email("邮箱", 0, 0),

    address("地址信息", 0, 0),

    ipv4("ipv4", 0, 0),

    ipv6("ipv6", 0, 0),

    defaultMode("默认模式", 0, 0);


    private String label;


    private int front;


    private int tail;


    DesensitizedMode(String label, int front, int tail) {
        this.label = label;
        this.front = front;
        this.tail = tail;
    }

    public String getLabel() {
        return label;
    }

    public int getFront() {
        return front;
    }

    public int getTail() {
        return tail;
    }
}
