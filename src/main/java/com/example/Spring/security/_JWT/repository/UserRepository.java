package com.example.Spring.security._JWT.repository;

import com.example.Spring.security._JWT.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = :attempts WHERE u.username = :username")
    void updateFailedAttempts(@Param("attempts") int attempts, @Param("username") String username);
}

