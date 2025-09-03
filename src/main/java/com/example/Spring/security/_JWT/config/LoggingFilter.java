package com.example.Spring.security._JWT.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.UUID;

@Component
@Slf4j
public class LoggingFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        long startTime = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString().substring(0, 8);

        // Логируем входящий запрос
        logIncomingRequest(request, requestId);

        try {
            filterChain.doFilter(request, response);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            // Логируем результат обработки
            logOutgoingResponse(request, response, duration, requestId);
        }
    }

    private void logIncomingRequest(HttpServletRequest request, String requestId) {
        String authHeader = request.getHeader("Authorization");
        String clientIP = getClientIP(request);

        if (log.isInfoEnabled()) {
            log.info("[{}] INCOMING_REQUEST -> IP: {}, Method: {}, URI: {}, Auth: {}",
                    requestId,
                    clientIP,
                    request.getMethod(),
                    request.getRequestURI(),
                    authHeader != null ? "Bearer token present" : "No auth"
            );
        }

        // Debug информация для разработки
        if (log.isDebugEnabled()) {
            log.debug("[{}] REQUEST_DETAILS -> Headers: {}, User-Agent: {}, Query: {}",
                    requestId,
                    getHeadersInfo(request),
                    request.getHeader("User-Agent"),
                    request.getQueryString() != null ? request.getQueryString() : "No query"
            );
        }
    }

    private void logOutgoingResponse(HttpServletRequest request, HttpServletResponse response,
                                     long duration, String requestId) {
        String username = getUsernameFromSecurityContext();
        int status = response.getStatus();

        // Разные уровни логирования в зависимости от статуса
        if (status >= 400 && status < 500) {
            log.warn("[{}] CLIENT_ERROR -> Status: {}, Duration: {}ms, User: {}, URI: {}",
                    requestId, status, duration, username, request.getRequestURI());
        } else if (status >= 500) {
            log.error("[{}] SERVER_ERROR -> Status: {}, Duration: {}ms, User: {}, URI: {}",
                    requestId, status, duration, username, request.getRequestURI());
        } else {
            log.info("[{}] SUCCESS -> Status: {}, Duration: {}ms, User: {}, URI: {}",
                    requestId, status, duration, username, request.getRequestURI());
        }

        // Логируем особые события безопасности
        logSecurityEvents(request, response, requestId);
    }

    private void logSecurityEvents(HttpServletRequest request, HttpServletResponse response, String requestId) {
        int status = response.getStatus();

        if (status == HttpStatus.UNAUTHORIZED.value()) {
            log.warn("[{}] SECURITY_EVENT -> UNAUTHORIZED access attempt to: {}",
                    requestId, request.getRequestURI());
        }

        if (status == HttpStatus.FORBIDDEN.value()) {
            String username = getUsernameFromSecurityContext();
            log.warn("[{}] SECURITY_EVENT -> FORBIDDEN access for user: {} to: {}",
                    requestId, username, request.getRequestURI());
        }
    }

    private String getClientIP(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    private String getUsernameFromSecurityContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() &&
                !(authentication instanceof AnonymousAuthenticationToken)) {
            return authentication.getName();
        }
        return "anonymous";
    }

    private String getHeadersInfo(HttpServletRequest request) {
        Enumeration<String> headerNames = request.getHeaderNames();
        StringBuilder headers = new StringBuilder();

        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            if (!headerName.equalsIgnoreCase("Authorization")) { // Исключаем токен
                headers.append(headerName).append(": ").append(request.getHeader(headerName));
                if (headerNames.hasMoreElements()) {
                    headers.append("; ");
                }
            }
        }

        return headers.toString();
    }

    // MDC для распределенного трейсинга (опционально)
    private void setupMdcContext(String requestId, HttpServletRequest request) {
        MDC.put("requestId", requestId);
        MDC.put("clientIP", getClientIP(request));
        MDC.put("requestURI", request.getRequestURI());
    }

    private void clearMdcContext() {
        MDC.remove("requestId");
        MDC.remove("clientIP");
        MDC.remove("requestURI");
    }

}
