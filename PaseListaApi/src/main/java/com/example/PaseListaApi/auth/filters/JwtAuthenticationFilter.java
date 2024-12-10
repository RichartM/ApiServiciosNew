package com.example.PaseListaApi.auth.filters;

import com.example.PaseListaApi.auth.AuthenticationProcessingException;
import com.example.PaseListaApi.auth.config.TokenJwtConfig;
import com.example.PaseListaApi.auth.model.AuthDetails;
import com.example.PaseListaApi.model.user_info.Users_info;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.example.PaseListaApi.auth.config.TokenJwtConfig.*;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final TokenJwtConfig tokenJwtConfig;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, TokenJwtConfig tokenJwtConfig) {
        this.authenticationManager = authenticationManager;
        this.tokenJwtConfig = tokenJwtConfig;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        Users_info user;
        String username;
        String password;
        try {
            user = new ObjectMapper().readValue(request.getInputStream(), Users_info.class);
            username= user.getEmail();
            password = user.getPassword();

        } catch (IOException e) {
            throw new AuthenticationProcessingException("Error al procesar la autenticación", e);
        }
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authToken);
    }
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        AuthDetails user = (AuthDetails) authResult.getPrincipal();
        String username= user.getEmail();
        Collection<? extends GrantedAuthority> roles = user.getAuthorities();

        Claims claims = Jwts.claims();
        claims.put("authorities",new ObjectMapper().writeValueAsString(roles));


        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .signWith(tokenJwtConfig.getSecretKey())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+3600000))
                .compact();
        response.addHeader(HEADER_AUTHORIZATION,PREFIX_TOKEN + token);

        Map<String,Object> body = new HashMap<>();
        body.put("token",token);
        body.put("email",username);
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(CONTENT_TYPE);

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        Map<String ,Object> body= new HashMap<>();
        body.put("messsage","Error en la autenticacion username o password es incorrecto");
        body.put("error",failed.getMessage());

        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setContentType(CONTENT_TYPE);

    }



}
