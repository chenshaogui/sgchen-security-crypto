package com.sgchen.security.transfer.register;

import com.sgchen.security.transfer.rsa.service.AsymmetricEncryptionKeyManageService;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

/**
 * 项目启动完后加载缺失的密钥对
 */
@Component
public class AsymmetricEncryptionKeyInitListener implements ApplicationListener<ContextRefreshedEvent> {

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        ApplicationContext applicationContext = event.getApplicationContext();
        if (applicationContext.containsBean("asymmetricEncryptionKeyManageService")) {
            AsymmetricEncryptionKeyManageService keyManageService = applicationContext.getBean(AsymmetricEncryptionKeyManageService.class);
            // 确保系统启动时有可用的RSA密钥对
            if (keyManageService.getLatestKeyPair() == null) {
                keyManageService.generateAndStoreNewKeyPair();
            }
        }

    }
}