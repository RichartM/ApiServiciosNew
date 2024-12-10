package com.example.PaseListaApi.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.PaseListaApi.model.Admin;

public interface AdminRepository extends JpaRepository<Admin, Long> {
    Admin findByCorreo(String correo);
}
