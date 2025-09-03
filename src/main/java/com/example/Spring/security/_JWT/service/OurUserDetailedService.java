package com.example.Spring.security._JWT.service;

import com.example.Spring.security._JWT.model.User;
import com.example.Spring.security._JWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class OurUserDetailedService implements UserDetailsService {

    private final UserRepository userRepository;
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION = 24 * 60 * 60 * 1000; // 24 часа


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        log.debug("Loading user details for username: {}", username);
        return user;
    }

    @Transactional
    public void increaseFailedAttempts(User user) {
        int newFailAttempts = user.getFailedAttempts() + 1;
        userRepository.updateFailedAttempts(newFailAttempts, user.getUsername());
        log.debug("Increased failed attempts for user {}: {}", user.getUsername(), newFailAttempts);

        if (newFailAttempts >= MAX_FAILED_ATTEMPTS) {
            lockUser(user);
        }
    }

    @Transactional
    public void lockUser(User user) {
        user.setAccountNonLocked(false);
        user.setLockTime(new Date());
        userRepository.save(user);
        log.info("User {} has been locked due to too many failed attempts", user.getUsername());
    }

    @Transactional
    public boolean unlockUser(User user) {
        if (user.getLockTime() == null) {
            log.warn("Attempt to unlock user {} who is not locked", user.getUsername());
            return false;
        }

        long lockTimeInMillis = user.getLockTime().getTime();
        long currentTimeInMillis = System.currentTimeMillis();

        if (lockTimeInMillis + LOCK_TIME_DURATION < currentTimeInMillis) {
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            user.setFailedAttempts(0);
            userRepository.save(user);
            log.info("User {} has been automatically unlocked", user.getUsername());
            return true;
        }
        log.debug("User {} is still locked until {}", user.getUsername(), new Date(lockTimeInMillis + LOCK_TIME_DURATION));
        return false;
    }

    @Transactional
    public void resetFailedAttempts(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        userRepository.updateFailedAttempts(0, username);
        // Если пользователь заблокирован, разблокируем его
        if (!user.isAccountNonLocked()) {
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            userRepository.save(user);
            log.info("Reset failed attempts and unlocked user {}", username);
        } else {
            log.debug("Reset failed attempts for user {}", username);
        }
    }
}
