package ru.itmo.secure;

import java.util.Map;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler(DuplicateKeyException.class)
    ResponseEntity<Map<String, String>> duplicate() { return ResponseEntity.status(409).body(Map.of("error", "username_exists")); }
    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    ResponseEntity<Map<String, String>> invalid() { return ResponseEntity.badRequest().body(Map.of("error", "invalid_input")); }
    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, String>> status(ResponseStatusException ex) {
        return ResponseEntity.status(ex.getStatusCode()).body(Map.of("error", ex.getStatusCode().value() == 401 ? "invalid_credentials" : "invalid_input"));
    }
}
