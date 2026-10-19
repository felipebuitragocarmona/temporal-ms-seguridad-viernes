package com.uc.ms_security.service;

import com.uc.ms_security.dto.user.CreateUserDTO;
import com.uc.ms_security.dto.user.UpdateUserDTO;
import com.uc.ms_security.dto.user.UserResponseDTO;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.mapper.UserMapper;
import com.uc.ms_security.repository.UserRepository;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserServicePasswordTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final UserMapper userMapper = mock(UserMapper.class);
    private final PasswordEncoder passwordEncoder = spy(new BCryptPasswordEncoder(4));
    private final UserService userService = new UserService(
            userRepository,
            userMapper,
            passwordEncoder
    );

    @BeforeEach
    void resetEncoderInteractions() {
        clearInvocations(passwordEncoder);
    }

    @Test
    void createStoresEncodedPasswordAndReturnsPasswordFreeResponse() {
        CreateUserDTO dto = createUserDTO("ClaveSegura123!");
        User user = new User();
        UserResponseDTO response = new UserResponseDTO(
                1L,
                "Ana Gómez",
                "ana@mail.com"
        );

        when(userRepository.existsByEmail(dto.getEmail())).thenReturn(false);
        when(userMapper.toEntity(eq(dto), anyString())).thenAnswer(invocation -> {
            user.setPassword(invocation.getArgument(1));
            return user;
        });
        when(userRepository.save(user)).thenReturn(user);
        when(userMapper.toResponseDTO(user)).thenReturn(response);

        UserResponseDTO result = userService.create(dto);

        assertEquals(response, result);
        assertNotEquals(dto.getPassword(), user.getPassword());
        assertTrue(passwordEncoder.matches(dto.getPassword(), user.getPassword()));
        verify(userMapper).toEntity(eq(dto), anyString());
    }

    @Test
    void updateWithoutPasswordPreservesExistingHash() {
        String existingHash = passwordEncoder.encode("ClaveAnterior123!");
        clearInvocations(passwordEncoder);
        User user = new User();
        user.setPassword(existingHash);
        UpdateUserDTO dto = updateUserDTO(null);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.existsByEmailAndIdNot(dto.getEmail(), 1L)).thenReturn(false);
        when(userRepository.save(user)).thenReturn(user);
        when(userMapper.toResponseDTO(user)).thenReturn(
                new UserResponseDTO(1L, dto.getName(), dto.getEmail())
        );

        userService.update(1L, dto);

        assertEquals(existingHash, user.getPassword());
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void updateWithNewPasswordStoresNewHash() {
        String existingHash = passwordEncoder.encode("ClaveAnterior123!");
        clearInvocations(passwordEncoder);
        User user = new User();
        user.setPassword(existingHash);
        UpdateUserDTO dto = updateUserDTO("ClaveNueva123!");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.existsByEmailAndIdNot(dto.getEmail(), 1L)).thenReturn(false);
        when(userRepository.save(user)).thenReturn(user);
        when(userMapper.toResponseDTO(user)).thenReturn(
                new UserResponseDTO(1L, dto.getName(), dto.getEmail())
        );

        userService.update(1L, dto);

        assertNotEquals(existingHash, user.getPassword());
        assertTrue(passwordEncoder.matches(dto.getPassword(), user.getPassword()));
        verify(passwordEncoder).encode(dto.getPassword());
    }

    @Test
    void passwordValidationMatchesTutorialRulesAndAllowsOmittedUpdatePassword() {
        try (var validatorFactory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = validatorFactory.getValidator();
            CreateUserDTO validCreate = createUserDTO("Clave123!");
            UpdateUserDTO updateWithoutPassword = updateUserDTO(null);
            List<String> invalidPasswords = List.of(
                    "clave123!",
                    "CLAVE123!",
                    "ClaveSegura!",
                    "Clave1234",
                    "Cla1!",
                    "Clave 123!",
                    "ClaveSegura123!" + "a".repeat(58)
            );

            assertFalse(validator.validate(validCreate).stream()
                    .anyMatch(error -> error.getPropertyPath().toString().equals("password")));
            for (String password : invalidPasswords) {
                assertTrue(validator.validate(createUserDTO(password)).stream()
                        .anyMatch(error -> error.getPropertyPath().toString().equals("password")),
                        password);
            }
            assertFalse(validator.validate(updateWithoutPassword).stream()
                    .anyMatch(error -> error.getPropertyPath().toString().equals("password")));
        }
    }

    private CreateUserDTO createUserDTO(String password) {
        CreateUserDTO dto = new CreateUserDTO();
        dto.setName("Ana Gómez");
        dto.setEmail("ana@mail.com");
        dto.setPassword(password);
        return dto;
    }

    private UpdateUserDTO updateUserDTO(String password) {
        UpdateUserDTO dto = new UpdateUserDTO();
        dto.setName("Ana Gómez");
        dto.setEmail("ana@mail.com");
        dto.setPassword(password);
        return dto;
    }
}
