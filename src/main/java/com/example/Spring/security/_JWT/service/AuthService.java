package com.example.Spring.security._JWT.service;

import com.example.Spring.security._JWT.dto.JwtResponse;
import com.example.Spring.security._JWT.exception.AuthenticationException;
import com.example.Spring.security._JWT.repository.UserRepository;
import com.example.Spring.security._JWT.utils.JWTUtils;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JWTUtils jwtUtils;
    private final OurUserDetailedService userDetailsService;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    public JwtResponse authenticateUser(String username, String password, String clientIP) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            String jwt = jwtUtils.generateToken(userDetails);
            String refreshToken = refreshTokenService.generateRefreshToken(userDetails);

            userDetailsService.resetFailedAttempts(username);

            log.info("User '{}' authenticated successfully from IP {}", username, clientIP);

            return new JwtResponse(jwt, refreshToken);

        } catch (BadCredentialsException e) {
            handleFailedLogin(username, clientIP);
            log.warn("Failed login attempt for user '{}' from IP {}", username, clientIP);
            throw new AuthenticationException("Invalid credentials", e);

        } catch (LockedException e) {
            log.warn("Locked account login attempt for user '{}' from IP {}", username, clientIP);
            throw new AuthenticationException("Account is locked", e);
        }
    }

    public JwtResponse refreshToken(String refreshToken) {
        try {
            String username = jwtUtils.extractUsername(refreshToken);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (refreshTokenService.isTokenValid(refreshToken, userDetails)) {
                String newJwt = jwtUtils.generateToken(userDetails);
                String newRefreshToken = refreshTokenService.generateRefreshToken(userDetails);

                log.info("Refresh token used to issue new JWT and refresh token for user '{}'", username);

                return new JwtResponse(newJwt, newRefreshToken);
            }

            log.warn("Invalid refresh token attempt for user '{}'", username);
            throw new AuthenticationException("Invalid refresh token");

        } catch (Exception e) {
            log.error("Exception during refresh token validation", e);
            throw new AuthenticationException("Invalid refresh token", e);
        }
    }

    private void handleFailedLogin(String username, String clientIP) {
        userRepository.findByUsername(username).ifPresent(user -> {
            userDetailsService.increaseFailedAttempts(user);
            int updatedAttempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(updatedAttempts);

            log.warn("Increased failed login attempts for user '{}' from IP {}. Current attempts: {}", username, clientIP, updatedAttempts);

            if (!user.isAccountNonLocked()) {
                log.warn("User  '{}' has been locked due to too many failed login attempts", username);
            }
        });
    }
    public void logout(String refreshToken) {
        try {
            refreshTokenService.revokeRefreshToken(refreshToken);
            SecurityContextHolder.clearContext();
            log.info("User  logged out and refresh token revoked");
        } catch (EntityNotFoundException e) {
            log.warn("Attempt to logout with non-existing refresh token");
        } catch (Exception e) {
            log.error("Error during logout", e);
        }
    }


}
