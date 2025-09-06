package com.example.Spring.security._JWT.service;

import com.example.Spring.security._JWT.model.RefreshToken;
import com.example.Spring.security._JWT.repository.RefreshTokenRepository;
import com.example.Spring.security._JWT.utils.JWTUtils;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.internal.util.stereotypes.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JWTUtils jwtUtils;

    // Генерация и сохранение нового refreshToken
    @Transactional
    public String generateRefreshToken(UserDetails userDetails) {

        String token = jwtUtils.generateRefreshToken(userDetails);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(token);
        refreshToken.setUserName(userDetails.getUsername());
        refreshToken.setExpiryDate(jwtUtils.extractExpiration(token));
        refreshToken.setRevoked(false);
        return token;
    }

    // Валидация refreshToken (с проверкой в БД)
    public boolean isTokenValid(String token, UserDetails userDetails) {
        // Базовые проверки через JWTUtils
        if (!jwtUtils.extractUsername(token).equals(userDetails.getUsername()) || jwtUtils.isTokenExpired(token)) {
            return false;
        }

        // Проверка в БД
        RefreshToken refreshTokenEntity = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new EntityNotFoundException("Refresh Token Not Found"));
        return refreshTokenEntity != null
                && !refreshTokenEntity.isRevoked()
                && refreshTokenEntity.getExpiryDate().after(new Date());
    }

    // Отзыв refreshToken
    @Transactional
    public void revokeRefreshToken(String token) {
        RefreshToken refreshTokenEntity = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new EntityNotFoundException("Refresh Token Not Found"));
        if (refreshTokenEntity != null) {
            refreshTokenEntity.setRevoked(true);
            refreshTokenRepository.save(refreshTokenEntity);
            log.info("RefreshToken revoked: {}", token);
        }
    }

    // Опционально: очистка истекших токенов
    @Transactional
    public void cleanExpiredTokens() {
        refreshTokenRepository.deleteByExpiryDateBefore(new Date());
        log.info("Expired refresh tokens cleaned");
    }

}
