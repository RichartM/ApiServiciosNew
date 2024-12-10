package com.example.PaseListaApi.auth;

public class AuthenticationProcessingException extends RuntimeException{
    public AuthenticationProcessingException(String message, Throwable cause) {
        super(message, cause);
    }
}