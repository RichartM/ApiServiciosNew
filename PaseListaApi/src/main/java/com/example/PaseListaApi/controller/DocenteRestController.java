package com.example.PaseListaApi.controller;


import com.example.PaseListaApi.model.Alumnos;
import com.example.PaseListaApi.model.Docentes;
import com.example.PaseListaApi.response.Alumnos.AlumnosResponseRest;
import com.example.PaseListaApi.response.Docente.DocenteResponseRest;
import com.example.PaseListaApi.service.Alumnos.AlumnosServiceImpl;
import com.example.PaseListaApi.service.Docentes.DocenteServiceImpl;
import com.example.PaseListaApi.service.Docentes.IDocenteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

//@CrossOrigin(origins = {"http://localhost:4200"})
@RestController
@RequestMapping("/v4")
public class DocenteRestController implements IDocenteService {
    private static final Logger log = LoggerFactory.getLogger(DocenteServiceImpl.class);
    @Autowired
    private DocenteServiceImpl docenteService;

    @GetMapping("/docente")
    public ResponseEntity<DocenteResponseRest> consultarDocentes() {
        ResponseEntity<DocenteResponseRest> response = docenteService.consultarDocentes();
        return response;
    }

    @Override
    @GetMapping("/docente/{id}")
    public ResponseEntity<DocenteResponseRest> consultarDocentesId(@PathVariable Long id) {
        ResponseEntity<DocenteResponseRest> response = docenteService.consultarDocentesId(id);
        return response;
    }
    @PostMapping("/docente")
    public ResponseEntity<DocenteResponseRest> crear(@RequestBody Docentes request){
        log.info("Inicio del metodo crear Docentes");
        System.out.println("id del docente en cuestion"+request.getId_docente());
        System.out.println("id del grupo en cuestion"+request.getGrupos().getId_grupo());
        ResponseEntity<DocenteResponseRest> response = docenteService.crear(request);
        return response;
    }
    @PutMapping("/docente/{id}")
    public ResponseEntity<DocenteResponseRest> actualizar(@RequestBody Docentes request, @PathVariable Long id){
        log.info("Inicio del metodo actualizar");
        ResponseEntity<DocenteResponseRest> response = docenteService.actualizar(request, id);
        return response;
    }

    @Override
    @PutMapping("/desactivar/{id}")
    public ResponseEntity<DocenteResponseRest> desactivarPorId(Long id) {
        log.info("Inicio del metodo DESACTIVAR");
        ResponseEntity<DocenteResponseRest> response = docenteService.desactivarPorId(id);
        return response;
    }

    @Override
    @PutMapping("/activar/{id}")
    public ResponseEntity<DocenteResponseRest> activarPorId(Long id) {
        log.info("Inicio del metodo DESACTIVAR");
        ResponseEntity<DocenteResponseRest> response = docenteService.desactivarPorId(id);
        return response;
    }
}
