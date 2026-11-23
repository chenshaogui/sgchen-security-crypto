package com.sgchen.security.transfer.filter;

import cn.hutool.extra.spring.SpringUtil;
import cn.hutool.http.HttpStatus;
import com.sgchen.security.core.config.SecretContext;
import com.sgchen.security.core.constant.SecurityConstants;
import com.sgchen.security.core.exception.AuthSecurityException;
import com.sgchen.security.transfer.util.RequestFilterUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @description  滤器实现对请求头的修改
 */
@WebFilter
@Component
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(
        prefix = "csg-security.request",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class DataSecurityDecryptFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse rsp = (HttpServletResponse) servletResponse;
        String contentType = req.getContentType();

        if (contentType != null && contentType.startsWith("multipart/")) {
            filterChain.doFilter(req, rsp); // 文件上传请求直接放行
            return;
        }
        // 获取请求路径
        String path = req.getRequestURI();
        if (path.contains("/api/asymmetricTSC")) {
            // 对公钥请求等接口放行
            filterChain.doFilter(req, rsp);
            return;
        }
        RequestMappingHandlerMapping handlerMapping = SpringUtil.getBean(RequestMappingHandlerMapping.class);
        HandlerExecutionChain handler = null;
        try {
            handler = handlerMapping.getHandler(req);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            errorReturn(rsp, 500, e.getMessage());
            return;
        }
        if (!RequestFilterUtil.hasDecryptAnnotation(handler)) {
            filterChain.doFilter(req, rsp); // 不包含注解直接放行
            return;
        }
        String feignHeader = req.getHeader(SecurityConstants.FEIGN_CLIENT_CALL);
        if (StringUtils.equals(feignHeader, "true")) {
            // feign客户端请求直接放行
            filterChain.doFilter(req, rsp);
            return;
        }
        EncryptHttpServletRequest headerMapRequestWrapper;
        try {
            SecretContext secretConfig = SpringUtil.getBean(SecretContext.class);
            headerMapRequestWrapper = new EncryptHttpServletRequest(req, secretConfig);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            if (e instanceof AuthSecurityException) {
                errorReturn(rsp, HttpStatus.HTTP_UNAUTHORIZED, e.getMessage());
                return;
            }
            errorReturn(rsp, HttpStatus.HTTP_INTERNAL_ERROR, e.getMessage());
            return;
        }
        // 放行
        filterChain.doFilter(headerMapRequestWrapper, servletResponse);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }

    private void errorReturn(HttpServletResponse httpServletResponse, Integer code, String message) throws IOException {
        httpServletResponse.setCharacterEncoding("UTF-8");
        httpServletResponse.setContentType("application/json;charset=utf-8");
        PrintWriter out = httpServletResponse.getWriter();
        String dataStr = String.format("{\"code\":%d,\"message\":\"%s\"}", code, message);
        out.write(dataStr);
        out.flush();
        out.close();
    }

}