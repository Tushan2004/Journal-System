package com.userservice.controller;

import com.userservice.dto.RegisterRequest;
import com.userservice.entity.User;
import com.userservice.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Map;

@RestController
@CrossOrigin(origins = {"http://localhost:5173", "http://localhost:3001"})
@RequestMapping("/users")
public class UserController {

    private final UserRepository userRepo;

    public UserController(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    // -------------------------
    // Public endpoint: register
    // -------------------------
    @PostMapping("/register")
    @Transactional
    public ResponseEntity<?> register(@RequestBody RegisterRequest r) {
        if (r.role() == null)
            return ResponseEntity.badRequest().body("Role is required");
        if (r.email() == null || r.email().isBlank())
            return ResponseEntity.badRequest().body("Email is required");
        if (r.password() == null || r.password().isBlank())
            return ResponseEntity.badRequest().body("Password is required");

        if (userRepo.findByEmail(r.email()).isPresent())
            return ResponseEntity.badRequest().body("Email already in use");

        User u = new User();
        u.setEmail(r.email());
        u.setRole(r.role());
        u.setPassword(r.password()); // OBS: lösenord behövs endast om du lagrar lokalt
        userRepo.save(u);

        return ResponseEntity.ok(Map.of(
                "id", u.getId(),
                "role", u.getRole()
        ));
    }

    // ----------------------------------------
    // Protected endpoint: visa info om nuvarande användare
    // ----------------------------------------
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getClaim("preferred_username"); // alltid satt
        Collection<String> roles = (Collection<String>) ((Map<String, Object>) jwt.getClaim("realm_access")).get("roles");

        return ResponseEntity.ok(Map.of(
                "username", username,
                "roles", roles
        ));
    }


    // ----------------------------------------
    // Protected endpoint: ADMIN only
    // ----------------------------------------
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Endast ADMIN kan se detta");
    }

    // ----------------------------------------
    // Protected endpoint: MANAGER only
    // ----------------------------------------
    @GetMapping("/manager")
    @PreAuthorize("hasRole('MANAGER')")
    public ResponseEntity<String> managerEndpoint() {
        return ResponseEntity.ok("Endast MANAGER kan se detta");
    }
}
