package com.userservice.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Konvertera Keycloak-roller till Spring Security authorities
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new JwtAuthConverter());

        http
                // Disable CSRF för enklare testing
                .csrf(csrf -> csrf.disable())

                // Definiera vilka endpoints som är offentliga
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/users/register").permitAll()  // publikt register
                        .anyRequest().authenticated()                    // alla andra endpoints kräver token
                )

                // Konfigurera JWT-baserad OAuth2 Resource Server
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                );

        return http.build();
    }
}
