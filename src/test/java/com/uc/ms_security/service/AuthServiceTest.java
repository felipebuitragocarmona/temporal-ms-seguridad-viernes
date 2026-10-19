package com.uc.ms_security.service;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.dto.LoginRequestDTO;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final JwtService jwtService = mock(JwtService.class);
    private final AuthService authService = new AuthService(
            userRepository,
            passwordEncoder,
            jwtService
    );

    @Test
    void loginWithValidCredentialsReturnsGeneratedToken() {
        LoginRequestDTO dto = loginRequest("ana@mail.com", "ClaveSegura123!");
        User user = new User();
        user.setId(7L);
        user.setEmail(dto.getEmail());
        user.setPassword("$2a$12$encoded-password");
        AuthResponseDTO response = new AuthResponseDTO(
                "signed.jwt.value",
                "Bearer",
                Instant.now().plusSeconds(900)
        );

        when(userRepository.findByEmail(dto.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(dto.getPassword(), user.getPassword())).thenReturn(true);
        when(jwtService.generateToken(user)).thenReturn(response);

        assertSame(response, authService.login(dto));
        verify(passwordEncoder).matches(dto.getPassword(), user.getPassword());
        verify(jwtService).generateToken(user);
    }

    @Test
    void loginWithUnknownEmailReturnsGenericUnauthorizedError() {
        LoginRequestDTO dto = loginRequest("missing@mail.com", "ClaveSegura123!");
        when(userRepository.findByEmail(dto.getEmail())).thenReturn(Optional.empty());

        ApplicationException exception = assertThrows(
                ApplicationException.class,
                () -> authService.login(dto)
        );

        assertEquals(ErrorCase.UNAUTHORIZED, exception.getErrorCase());
        assertEquals("Credenciales incorrectas", exception.getMessage());
        verify(jwtService, never()).generateToken(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void loginWithIncorrectPasswordReturnsSameGenericUnauthorizedError() {
        LoginRequestDTO dto = loginRequest("ana@mail.com", "Incorrecta123!");
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPassword("$2a$12$encoded-password");

        when(userRepository.findByEmail(dto.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(dto.getPassword(), user.getPassword())).thenReturn(false);

        ApplicationException exception = assertThrows(
                ApplicationException.class,
                () -> authService.login(dto)
        );

        assertEquals(ErrorCase.UNAUTHORIZED, exception.getErrorCase());
        assertEquals("Credenciales incorrectas", exception.getMessage());
        verify(jwtService, never()).generateToken(org.mockito.ArgumentMatchers.any());
    }

    private LoginRequestDTO loginRequest(String email, String password) {
        LoginRequestDTO dto = new LoginRequestDTO();
        dto.setEmail(email);
        dto.setPassword(password);
        return dto;
    }
}
