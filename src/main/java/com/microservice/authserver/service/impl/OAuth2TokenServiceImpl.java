package com.microservice.authserver.service.impl;

import com.microservice.authserver.dto.LoginRequest;
import com.microservice.authserver.dto.TokenResponse;
import com.microservice.authserver.service.OAuth2TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class OAuth2TokenServiceImpl implements OAuth2TokenService {


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;


    /**
     * Authenticates user credentials and generates OAuth 2.0 access token
     *  Implements your 5-step authentication flow:
     *  1. Authenticate user with username and password from loginRequest
     *  2. Set authentication true if authenticated else throw exception
     *  3. Retrieve user details
     *  4. Create token with necessary details
     *  5. Create TokenResponse object
     *
     * @param loginRequest contains username and password for authentication
     * @return TokenResponse containing access_token, refresh_token, token_type, and expires_in
     * @throws AuthenticationException if credentials are invalid
     */
    @Override
    public TokenResponse generateAccessToken(LoginRequest loginRequest) {

        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            String username = authentication.getName();
            Set<String> authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

            String accessToken = createJwtAccessToken(username, authorities);
            String refreshToken = generateRefreshToken(username);
            long expiresIn = 3600;
            return new TokenResponse(accessToken, refreshToken, expiresIn);

        } catch (AuthenticationException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * Creates JWT access token with user information and roles
     * Token contains: username, roles, issuer, expiration, audience
     */
    private String createJwtAccessToken(String username, Set<String> authorities) {
        Instant now = Instant.now();
        Instant expiry = now.plus(1, ChronoUnit.HOURS);

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("http://localhost:9001")
                .subject(username)
                .audience(List.of("microservice-client-id"))
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("authorities", authorities)
                .claim("token_type", "access")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    /**
     * Generates a new refresh token for the given username
     * Used for obtaining new access tokens without re-authentication
     *
     * @param username the username for whom to generate refresh token
     * @return refresh token as JWT string
     */
    @Override
    public String generateRefreshToken(String username) {
        Instant now = Instant.now();
        Instant expiry = now.plus(30, ChronoUnit.DAYS);

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("http://localhost:9001")
                .subject(username)
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("token_type", "refresh")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    /**
     * Validates the provided access token
     * Checks signature, expiration, and issuer
     *
     * @param token the JWT access token to validate
     * @return true if token is valid, false otherwise
     */
    @Override
    public boolean validateAccessToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            Instant expiration = jwt.getExpiresAt();

            if(expiration != null && expiration.isBefore(Instant.now())){
                return false;
            }

            String tokenType = jwt.getClaim("token_type");

            return "access".equals(tokenType);
        } catch (JwtException e) {
            return false;
        }
    }

    /**
     * Extracts username from a valid access token
     * Useful for microservices to identify the authenticated user
     *
     * @param token the JWT access token
     * @return username (subject) from the token
     * @throws RuntimeException if token is invalid or expired
     */
    @Override
    public String extractUsernameFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getSubject();
        } catch (JwtException exception) {
            throw new RuntimeException("Invalid token");
        }
    }
}
