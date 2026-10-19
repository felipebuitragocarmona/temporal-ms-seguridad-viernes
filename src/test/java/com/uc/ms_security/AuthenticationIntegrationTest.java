package com.uc.ms_security;

import com.uc.ms_security.entity.User;
import com.uc.ms_security.repository.UserRepository;
import com.uc.ms_security.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthenticationIntegrationTest {

    private static final String TEST_PASSWORD = "ClaveSegura123!";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Test
    void protectedEndpointRejectsRequestWithoutToken() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Transactional
    void loginReturnsBearerTokenThatCanAccessProtectedEndpoint() throws Exception {
        String email = "jwt-test-" + UUID.randomUUID() + "@mail.com";
        User user = new User();
        user.setName("JWT Test");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(TEST_PASSWORD));
        userRepository.saveAndFlush(user);

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, TEST_PASSWORD)))
                .andExpect(status().isOk())
                .andReturn();

        Matcher tokenMatcher = Pattern.compile(
                "\"accessToken\"\\s*:\\s*\"([A-Za-z0-9._-]+)\""
        ).matcher(loginResult.getResponse().getContentAsString());
        if (!tokenMatcher.find()) {
            throw new AssertionError("Login response did not contain an access token");
        }

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + tokenMatcher.group(1)))
                .andExpect(status().isOk());
    }

    @Test
    void loginWithUnknownEmailReturnsUnauthorized() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "missing-%s@mail.com",
                                  "password": "%s"
                                }
                                """.formatted(UUID.randomUUID(), TEST_PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointRejectsTamperedToken() throws Exception {
        User user = new User();
        user.setId(7L);
        user.setEmail("ana@mail.com");
        String token = jwtService.generateToken(user).accessToken();
        String tamperedToken = token.substring(0, token.lastIndexOf('.') + 1)
                + "AAAAAAAA";

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + tamperedToken))
                .andExpect(status().isUnauthorized());
    }
}
