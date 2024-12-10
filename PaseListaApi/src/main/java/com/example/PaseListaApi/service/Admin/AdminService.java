package com.example.PaseListaApi.service.Admin;

import com.example.PaseListaApi.dao.AdminRepository;
import com.example.PaseListaApi.model.Admin;
import com.example.PaseListaApi.model.user_info.User_infoRepository;
import com.example.PaseListaApi.model.user_info.Users_info;
import com.example.PaseListaApi.response.Admin.AdminResponseRest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AdminService {

    private static final Logger log = LoggerFactory.getLogger(AdminService.class);

    @Autowired
    private AdminRepository adminRepository;

    @Autowired
    private User_infoRepository userInfoRepository; // Necesario para guardar en users_info

    public ResponseEntity<AdminResponseRest> crear(Admin admin) {
        log.info("Creación de administrador");
        AdminResponseRest response = new AdminResponseRest();
        List<Admin> listaAdmin = new ArrayList<>();
        try {
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            admin.setPassword(passwordEncoder.encode(admin.getPassword()));

            Users_info newUser = new Users_info(null, admin.getCorreo(), admin.getPassword(), "Administrador");
            this.userInfoRepository.save(newUser);

            Admin adminGuardado = adminRepository.save(admin);
            if (adminGuardado != null) {
                listaAdmin.add(adminGuardado);
                response.getAdminResponse().setAdmins(listaAdmin);
                response.setMetada("Respuesta OK", "00", "CREACIÓN EXITOSA");
                return new ResponseEntity<>(response, HttpStatus.OK);
            } else {
                log.info("No se agregó el administrador");
                response.setMetada("No se agregó el administrador", "-1", "Error en la creación");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            response.setMetada("Error", "-1", "Error al crear administrador");
            log.error("No se pudo crear el administrador", e);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public List<Admin> getAllAdmins() {
        return adminRepository.findAll();
    }

    public Admin getAdminByCorreo(String correo) {
        return adminRepository.findByCorreo(correo);
    }

    public Optional<Admin> getAdminById(Long id) {
        return adminRepository.findById(id);
    }

    public void deleteAdmin(Long id) {
        adminRepository.deleteById(id);
    }
}
