package ru.itmo.secure;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class ApiController {
    private final Users users;
    private final PasswordEncoder passwords;
    private final JwtEncoder tokens;
    private final String dummyHash;
    public ApiController(Users users, PasswordEncoder passwords, JwtEncoder tokens) {
        this.users = users; this.passwords = passwords; this.tokens = tokens;
        this.dummyHash = passwords.encode(java.util.UUID.randomUUID().toString());
    }
    public record Registration(@NotBlank @Size(max=64) String username,
        @NotBlank @Size(min=12, max=72) String password, @NotNull @Min(0) @Max(150) Integer age) {}
    public record Login(@NotBlank @Size(max=64) String username, @NotBlank @Size(max=72) String password) {}
    public record Token(String token, String tokenType, long expiresIn) {}
    private static void checkPasswordBytes(String password) {
        if (password.getBytes(StandardCharsets.UTF_8).length > 72)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }
    @PostMapping("/auth/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Users.Profile register(@Valid @RequestBody Registration input) {
        checkPasswordBytes(input.password());
        return users.create(input.username(), passwords.encode(input.password()), input.age());
    }
    @PostMapping("/auth/login")
    public Token login(@Valid @RequestBody Login input) {
        checkPasswordBytes(input.password());
        var account = users.find(input.username());
        boolean matches = passwords.matches(input.password(), account.map(Users.Account::hash).orElse(dummyHash));
        if (!matches || account.isEmpty()) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer(SecurityConfig.ISSUER).audience(List.of(SecurityConfig.AUDIENCE))
            .subject(Long.toString(account.get().id())).issuedAt(now).expiresAt(now.plusSeconds(900)).build();
        return new Token(tokens.encode(JwtEncoderParameters.from(
            JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue(), "Bearer", 900);
    }
    @GetMapping("/api/data")
    public List<Users.Profile> data(@RequestParam(defaultValue="0") int page, @RequestParam(defaultValue="20") int size) {
        if (page < 0 || page > 100000 || size < 1 || size > 100)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        return users.list(page, size);
    }
}
