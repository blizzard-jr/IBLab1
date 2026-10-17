package ru.itmo.secure;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = "spring.datasource.url=${TEST_DB_URL:jdbc:postgresql://localhost:55432/secure_api_test}")
@AutoConfigureMockMvc
class ApiIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtEncoder encoder;
    private static final String PASSWORD = "Test-password-123!";
    @BeforeEach void reset() { jdbc.update("DELETE FROM app_users"); }
    private ResultActions postJson(String url, Object body) throws Exception {
        return mvc.perform(post(url).contentType("application/json").content(json.writeValueAsString(body)));
    }
    private ResultActions register(String username) throws Exception {
        return postJson("/auth/register", Map.of("username",username,"password",PASSWORD,"age",21));
    }
    private String login(String username) throws Exception {
        var response = postJson("/auth/login", Map.of("username",username,"password",PASSWORD))
            .andExpect(status().isOk()).andExpect(jsonPath("tokenType").value("Bearer"))
            .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("token").asText();
    }
    @Test void registrationLoginAndData() throws Exception {
        register("leonard").andExpect(status().isCreated()).andExpect(jsonPath("age").value(21))
            .andExpect(jsonPath("password").doesNotExist()).andExpect(jsonPath("hash").doesNotExist());
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + login("leonard")))
            .andExpect(status().isOk()).andExpect(jsonPath("$[0].username").value("leonard"))
            .andExpect(jsonPath("$[0].password_hash").doesNotExist())
            .andExpect(header().string("X-Content-Type-Options", "nosniff"))
            .andExpect(header().doesNotExist("Set-Cookie"));
    }
    @Test void passwordIsSaltedBcrypt() throws Exception {
        register("one"); register("two");
        var hashes = jdbc.queryForList("SELECT password_hash FROM app_users ORDER BY id", String.class);
        assertThat(hashes).hasSize(2);
        assertThat(hashes.get(0)).startsWith("$2a$12$").isNotEqualTo(PASSWORD).isNotEqualTo(hashes.get(1));
        assertThat(passwords.matches(PASSWORD, hashes.get(0))).isTrue();
    }
    @Test void anonymousIsRejected() throws Exception {
        mvc.perform(get("/api/data")).andExpect(status().isUnauthorized());
    }
    @Test void badCredentialsAreIndistinguishable() throws Exception {
        register("real");
        for (String username : List.of("real", "missing"))
            postJson("/auth/login", Map.of("username", username, "password", "wrong-password"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("error").value("invalid_credentials"));
    }
    @Test void duplicateUsernameIsConflict() throws Exception {
        register("same").andExpect(status().isCreated());
        register("same").andExpect(status().isConflict());
    }
    @Test void validatesRegistration() throws Exception {
        for (int age : List.of(-1, 151))
            postJson("/auth/register", Map.of("username","test","password",PASSWORD,"age",age))
                .andExpect(status().isBadRequest());
        postJson("/auth/register", Map.of("username"," ","password",PASSWORD,"age",21)).andExpect(status().isBadRequest());
        postJson("/auth/register", Map.of("username","test","password","short","age",21)).andExpect(status().isBadRequest());
        postJson("/auth/register", Map.of("username","test","password",PASSWORD)).andExpect(status().isBadRequest());
    }
    @Test void rejectsBcryptUtf8Truncation() throws Exception {
        postJson("/auth/register", Map.of("username","test","password","я".repeat(37),"age",21))
            .andExpect(status().isBadRequest());
    }
    @Test void malformedJsonIsBadRequest() throws Exception {
        mvc.perform(post("/auth/register").contentType("application/json").content("{"))
            .andExpect(status().isBadRequest());
    }
    @Test void sqlInjectionCannotBypassLogin() throws Exception {
        register("real");
        postJson("/auth/login", Map.of("username", "' OR '1'='1' --", "password", PASSWORD))
            .andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM app_users", Integer.class)).isEqualTo(1);
    }
    @Test void sqlCharactersAreStoredAsData() throws Exception {
        String username = "x'; DROP TABLE app_users; --";
        register(username).andExpect(status().isCreated());
        login(username);
        assertThat(jdbc.queryForObject("SELECT username FROM app_users", String.class)).isEqualTo(username);
    }
    @Test void xssIsEscapedInBothResponses() throws Exception {
        String username = "<script>alert(1)</script>";
        String escaped = "&lt;script&gt;alert(1)&lt;/script&gt;";
        register(username).andExpect(status().isCreated()).andExpect(jsonPath("username").value(escaped));
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + login(username)))
            .andExpect(status().isOk()).andExpect(jsonPath("$[0].username").value(escaped));
    }
    @Test void malformedAndTamperedTokensAreRejected() throws Exception {
        register("real");
        String token = login("real");
        int signature = token.lastIndexOf('.') + 1;
        String tampered = token.substring(0,signature) + (token.charAt(signature) == 'A' ? "B" : "A") + token.substring(signature+1);
        for (String candidate : List.of("garbage", tampered, "eyJhbGciOiJub25lIn0.e30."))
            mvc.perform(get("/api/data").header("Authorization", "Bearer " + candidate))
                .andExpect(status().isUnauthorized());
    }
    private String token(Instant expiry, String issuer, String audience) {
        var claims = JwtClaimsSet.builder().issuer(issuer).audience(List.of(audience)).subject("1")
            .issuedAt(Instant.now().minusSeconds(120)).expiresAt(expiry).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),claims)).getTokenValue();
    }
    @Test void expiredTokenIsRejected() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + token(Instant.now().minusSeconds(10),SecurityConfig.ISSUER,SecurityConfig.AUDIENCE)))
            .andExpect(status().isUnauthorized());
    }
    @Test void wrongIssuerAndAudienceAreRejected() throws Exception {
        for (String candidate : List.of(token(Instant.now().plusSeconds(300),"wrong",SecurityConfig.AUDIENCE),
                token(Instant.now().plusSeconds(300),SecurityConfig.ISSUER,"wrong")))
            mvc.perform(get("/api/data").header("Authorization", "Bearer " + candidate)).andExpect(status().isUnauthorized());
    }
    @Test void missingExpiryIsRejected() throws Exception {
        var claims = JwtClaimsSet.builder().issuer(SecurityConfig.ISSUER).audience(List.of(SecurityConfig.AUDIENCE))
            .subject("1").issuedAt(Instant.now()).build();
        String candidate = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),claims)).getTokenValue();
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + candidate)).andExpect(status().isUnauthorized());
    }
    @Test void paginationIsBounded() throws Exception {
        register("first"); register("second"); String token = login("first");
        mvc.perform(get("/api/data?page=1&size=1").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1)).andExpect(jsonPath("$[0].username").value("second"));
        mvc.perform(get("/api/data?size=101").header("Authorization", "Bearer " + token)).andExpect(status().isBadRequest());
    }
    @Test void queryTokenAndBasicAuthAreNotAccepted() throws Exception {
        register("real");
        mvc.perform(get("/api/data").param("access_token", login("real"))).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/data").header("Authorization", "Basic cmVhbDpUZXN0LXBhc3N3b3JkLTEyMyE="))
            .andExpect(status().isUnauthorized());
    }
}
