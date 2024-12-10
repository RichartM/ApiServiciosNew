package com.example.PaseListaApi.auth.filters;

import com.example.PaseListaApi.auth.config.TokenJwtConfig;
import com.example.PaseListaApi.auth.utils.SimpleGrantedAuthorityJsonCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.example.PaseListaApi.auth.config.TokenJwtConfig.*;

public class JwtValidationFilter extends BasicAuthenticationFilter {
    private final TokenJwtConfig tokenJwtConfig;

    public JwtValidationFilter(AuthenticationManager authenticationManager, TokenJwtConfig tokenJwtConfig) {
        super(authenticationManager);
        this.tokenJwtConfig = tokenJwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header= request.getHeader(HEADER_AUTHORIZATION);
        if(header == null || !header.startsWith(PREFIX_TOKEN)){
            chain.doFilter(request,response);
            return;
        }

        String token = header.replace(PREFIX_TOKEN,"");


        try{
            Claims claims =  Jwts.parserBuilder().setSigningKey(tokenJwtConfig.getSecretKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Object authoritiesClaims= claims.get("authorities");
            String   username = claims.getSubject();

            Collection<? extends GrantedAuthority> authorities = List.of(new ObjectMapper()
                    .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityJsonCreator.class)
                    .readValue(authoritiesClaims.toString().getBytes(), SimpleGrantedAuthority[].class));
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null,authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request,response);
        }catch (JwtException e){
            Map<String,String> body = new HashMap<>();
            body.put("error",e.getMessage());
            body.put("message","el token no es valido");

            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(CONTENT_TYPE);
        }


    }
}
