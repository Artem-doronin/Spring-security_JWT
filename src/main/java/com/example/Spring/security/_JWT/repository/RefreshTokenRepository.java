package com.example.Spring.security._JWT.repository;

import com.example.Spring.security._JWT.model.RefreshToken;
import com.example.Spring.security._JWT.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    // Найти refresh-токен по хэшированному токену
    Optional<RefreshToken> findByToken(String token);

    // Удалить просроченные токены (для очистки) - производный метод
    @Modifying
    int deleteByExpiryDateBefore(Date date);

    // Альтернативный метод с @Query (если хотите больше контроля)
    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.expiryDate < :date")
    int deleteExpiredTokens(Date date);
}
