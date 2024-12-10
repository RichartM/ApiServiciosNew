package com.example.PaseListaApi.auth.config;
import io.jsonwebtoken.security.Keys;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Getter
@Configuration
public class TokenJwtConfig {
    public final SecretKey secretKey;
    public static final String PREFIX_TOKEN = "Bearer ";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String CONTENT_TYPE = "application/json";

    public TokenJwtConfig(@Value("${jwt.secret}") String secret) {
        this.secretKey = Keys.  hmacShaKeyFor(secret.getBytes());
    }

}
