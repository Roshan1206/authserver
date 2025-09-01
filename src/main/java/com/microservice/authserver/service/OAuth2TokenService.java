package com.microservice.authserver.service;

import com.microservice.authserver.dto.LoginRequest;
import com.microservice.authserver.dto.TokenResponse;

/**
 * Service interface for OAuth 2.0 token operations
 * Handles authentication, token generation, and token validation
 * 
 * @author Roshan
 */
public interface OAuth2TokenService {

    /**
     * Authenticates user credentials and generates OAuth 2.0 access token
     * 
     * @param loginRequest contains username and password for authentication
     * @return TokenResponse containing access_token, refresh_token, token_type, and expires_in
     * @throws AuthenticationException if credentials are invalid
     */
    TokenResponse generateAccessToken(LoginRequest loginRequest);

    /**
     * Generates a new refresh token for the given username
     * Used for obtaining new access tokens without re-authentication
     * 
     * @param username the username for whom to generate refresh token
     * @return refresh token as JWT string
     */
    String generateRefreshToken(String username);

    /**
     * Validates the provided access token
     * Checks signature, expiration, and issuer
     * 
     * @param token the JWT access token to validate
     * @return true if token is valid, false otherwise
     */
    boolean validateAccessToken(String token);

    /**
     * Extracts username from a valid access token
     * Useful for microservices to identify the authenticated user
     * 
     * @param token the JWT access token
     * @return username (subject) from the token
     * @throws RuntimeException if token is invalid or expired
     */
    String extractUsernameFromToken(String token);
}