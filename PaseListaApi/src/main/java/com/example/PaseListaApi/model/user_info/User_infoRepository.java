package com.example.PaseListaApi.model.user_info;

import org.springframework.data.jpa.repository.JpaRepository;

public interface User_infoRepository extends JpaRepository<Users_info,Long> {
    Users_info findByEmail(String email);
}
