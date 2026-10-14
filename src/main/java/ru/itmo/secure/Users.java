package ru.itmo.secure;

import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.web.util.HtmlUtils;

@Repository
public class Users {
    private final JdbcTemplate jdbc;
    public Users(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    public record Account(long id, String username, String hash, int age) {}
    public record Profile(long id, String username, int age) {}
    public Optional<Account> find(String username) {
        return jdbc.query("SELECT id, username, password_hash, age FROM app_users WHERE username = ?",
            (rs, row) -> new Account(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getInt(4)), username)
            .stream().findFirst();
    }
    public Profile create(String username, String hash, int age) {
        return jdbc.queryForObject("INSERT INTO app_users(username, password_hash, age) VALUES (?, ?, ?) RETURNING id, username, age",
            (rs, row) -> new Profile(rs.getLong(1), HtmlUtils.htmlEscape(rs.getString(2)), rs.getInt(3)),
            username, hash, age);
    }
    public List<Profile> list(int page, int size) {
        return jdbc.query("SELECT id, username, age FROM app_users ORDER BY id LIMIT ? OFFSET ?",
            (rs, row) -> new Profile(rs.getLong(1), HtmlUtils.htmlEscape(rs.getString(2)), rs.getInt(3)), size, page * size);
    }
}
