package com.example.PaseListaApi.controller;
import com.example.PaseListaApi.model.Admin;
import com.example.PaseListaApi.response.Admin.AdminResponseRest;
import com.example.PaseListaApi.service.Admin.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/admins")
public class AdminController {

    @Autowired
    private AdminService adminService;

    @PostMapping
    public ResponseEntity<AdminResponseRest> crearAdmin(@RequestBody Admin admin) {
        return adminService.crear(admin);
    }

    @GetMapping
    public ResponseEntity<List<Admin>> obtenerTodosLosAdmins() {
        List<Admin> admins = adminService.getAllAdmins();
        return ResponseEntity.ok(admins);
    }

    @GetMapping("/correo/{correo}")
    public ResponseEntity<Admin> obtenerAdminPorCorreo(@PathVariable String correo) {
        Admin admin = adminService.getAdminByCorreo(correo);
        if (admin != null) {
            return ResponseEntity.ok(admin);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<Admin> obtenerAdminPorId(@PathVariable Long id) {
        Optional<Admin> admin = adminService.getAdminById(id);
        return admin.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> eliminarAdmin(@PathVariable Long id) {
        try {
            adminService.deleteAdmin(id);
            return ResponseEntity.ok("Administrador eliminado correctamente");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error al eliminar el administrador");
        }
    }
}
