package com.example.PaseListaApi.controller;

import com.example.PaseListaApi.model.Grupos;
import com.example.PaseListaApi.response.Grupos.GrupoResponseRest;
import com.example.PaseListaApi.service.Grupos.GrupoServiceImpl;
import com.example.PaseListaApi.service.Grupos.IGruposService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@CrossOrigin(origins = {"http://localhost:4200"})
@RestController
@RequestMapping("/v1")
public class GrupoRestController implements IGruposService {
    private static final Logger log = LoggerFactory.getLogger(GrupoServiceImpl.class);
    @Autowired
    private GrupoServiceImpl grupoService;

    //Consulta todos los grupos
    @GetMapping("/grupos")
    public ResponseEntity<GrupoResponseRest> consultarGrupos(){
        ResponseEntity<GrupoResponseRest> response =grupoService.consultarGrupos();
        return response;
    }
    //Editamos grupos excepto id
    @Override
    @PutMapping("/grupos/{id}")
    public ResponseEntity<GrupoResponseRest> actualizarGrupos(@RequestBody Grupos grupos, @PathVariable Long id) {
        ResponseEntity<GrupoResponseRest> response =grupoService.actualizarGrupos(grupos, id);
        return response;
    }



    //Consultamos grupos por id
    @GetMapping("/grupos/{id}")
    public ResponseEntity<GrupoResponseRest> consultarGrupoId(@PathVariable Long id) {
        ResponseEntity<GrupoResponseRest> response =grupoService.consultarGrupoId(id);
        return response;
    }
    //Añadimos grupos
    @PostMapping("/grupos")
    public ResponseEntity<GrupoResponseRest> crear(@RequestBody Grupos request) {
        log.info("Inicio del mecotdo crear GRUPOS");
        ResponseEntity<GrupoResponseRest> response = grupoService.crear(request);
        return response;
    }
    @PutMapping("/desactivar/{id}")
    public ResponseEntity<GrupoResponseRest> desactivarPorId(@PathVariable Long id) {
        ResponseEntity<GrupoResponseRest> response =grupoService.desactivarPorId(id);
        return response;
    }
    @PutMapping("/activar/{id}")
    public ResponseEntity<GrupoResponseRest> activarPorId(@PathVariable Long id) {
        ResponseEntity<GrupoResponseRest> response =grupoService.activarPorId(id);
        return response;
    }

}
