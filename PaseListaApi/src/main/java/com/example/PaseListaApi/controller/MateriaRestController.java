package com.example.PaseListaApi.controller;

import com.example.PaseListaApi.model.Materia;
import com.example.PaseListaApi.response.Materia.MateriaResponseRest;
import com.example.PaseListaApi.service.Materia.IMateriaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v2")
@CrossOrigin(origins = {"http://localhost:4200"})
public class MateriaRestController {

    @Autowired
    private IMateriaService materiaService;

    // Consulta todas las materias
    @GetMapping("/materias")
    public ResponseEntity<MateriaResponseRest> buscarMaterias() {
        ResponseEntity<MateriaResponseRest> response = materiaService.buscarMaterias();
        return response;
    }

    // Consultar materia por ID
    @GetMapping("/materias/{id}")
    public ResponseEntity<MateriaResponseRest> buscarMateriaPorId(@PathVariable Long id) {
        ResponseEntity<MateriaResponseRest> response = materiaService.buscarMateriaPorId(id);
        return response;
    }

    // Crear una nueva materia
    @PostMapping("/materias")
    public ResponseEntity<MateriaResponseRest> crearMateria(@RequestBody Materia materia) {
        ResponseEntity<MateriaResponseRest> response = materiaService.crearMateria(materia);
        return response;
    }

    // Actualizar materia, excepto id
    @PutMapping("/materias/{id}")
    public ResponseEntity<MateriaResponseRest> actualizarMateria(@RequestBody Materia materia, @PathVariable Long id) {
        ResponseEntity<MateriaResponseRest> response = materiaService.actualizarMateria(materia, id);
        return response;
    }

    // Desactivar materia por ID
    @PutMapping("/materias/desactivar/{id}")
    public ResponseEntity<MateriaResponseRest> desactivarMateriaPorId(@PathVariable Long id) {
        ResponseEntity<MateriaResponseRest> response = materiaService.desactivarMateriaPorId(id);
        return response;
    }

    // Activar materia por ID
    @PutMapping("/materias/activar/{id}")
    public ResponseEntity<MateriaResponseRest> activarMateriaPorId(@PathVariable Long id) {
        ResponseEntity<MateriaResponseRest> response = materiaService.activarMateriaPorId(id);
        return response;
    }
}
