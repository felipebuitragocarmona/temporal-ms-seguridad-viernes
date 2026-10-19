package com.uc.ms_security.service;

import com.uc.ms_security.config.JwtConfig;
import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;

import javax.crypto.SecretKey;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {

    private static final String SECRET = "test-only-jwt-secret-with-at-least-32-bytes";

    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        JwtConfig jwtConfig = new JwtConfig();
        SecretKey secretKey = jwtConfig.jwtSecretKey(SECRET);
        jwtEncoder = jwtConfig.jwtEncoder(secretKey);
        jwtDecoder = jwtConfig.jwtDecoder(secretKey);
        jwtService = new JwtService(jwtEncoder);
    }

    @Test
    void generatedTokenContainsExpectedClaimsAndCanBeDecoded() {
        User user = new User();
        user.setId(7L);
        user.setEmail("ana@mail.com");
        user.setPassword("must-not-be-in-token");

        AuthResponseDTO response = jwtService.generateToken(user);

        var decoded = jwtDecoder.decode(response.accessToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(JwtConfig.JWT_ISSUER, decoded.getIssuer().toString());
        assertEquals("7", decoded.getSubject());
        assertEquals("ana@mail.com", decoded.getClaimAsString("email"));
        assertNotNull(decoded.getId());
        assertEquals(decoded.getExpiresAt(), response.expiresAt());
        assertEquals(15 * 60, response.expiresAt().getEpochSecond()
                - decoded.getIssuedAt().getEpochSecond());
    }

    @Test
    void decoderRejectsTamperedToken() {
        User user = new User();
        user.setId(7L);
        user.setEmail("ana@mail.com");
        String token = jwtService.generateToken(user).accessToken();
        String tamperedToken = token.substring(0, token.lastIndexOf('.') + 1)
                + "AAAAAAAA";

        assertThrows(JwtException.class, () -> jwtDecoder.decode(tamperedToken));
    }

    @Test
    void decoderRejectsExpiredToken() {
        Instant now = Instant.now();
        JwtClaimsSet expiredClaims = JwtClaimsSet.builder()
                .issuer(JwtConfig.JWT_ISSUER)
                .subject("7")
                .issuedAt(now.minusSeconds(120))
                .expiresAt(now.minusSeconds(60))
                .build();
        String expiredToken = jwtEncoder.encode(
                JwtEncoderParameters.from(
                        JwsHeader.with(MacAlgorithm.HS256).build(),
                        expiredClaims
                )
        ).getTokenValue();

        assertThrows(JwtException.class, () -> jwtDecoder.decode(expiredToken));
    }

    @Test
    void jwtSecretMustContainAtLeast32Utf8Bytes() {
        JwtConfig jwtConfig = new JwtConfig();

        assertThrows(
                IllegalStateException.class,
                () -> jwtConfig.jwtSecretKey("too-short")
        );
    }
}
