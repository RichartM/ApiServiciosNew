package com.example.PaseListaApi.model.user_info;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="users_info")
public class Users_info {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id_user;
    @Column(name = "email",nullable = false,columnDefinition = "text")
    private String email;
    @Column(name = "password",nullable = false,columnDefinition = "text")
    private String password;
    @Column(name = "rol",nullable = false,columnDefinition = "VARCHAR(15)")
    private String rol;
}
