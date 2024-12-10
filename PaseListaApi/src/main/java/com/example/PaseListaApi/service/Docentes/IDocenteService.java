package com.example.PaseListaApi.service.Docentes;

import com.example.PaseListaApi.model.Alumnos;
import com.example.PaseListaApi.model.Docentes;
import com.example.PaseListaApi.response.Alumnos.AlumnosResponseRest;
import com.example.PaseListaApi.response.Docente.DocenteResponseRest;
import com.example.PaseListaApi.response.Grupos.GrupoResponseRest;
import org.springframework.http.ResponseEntity;

public interface IDocenteService {
    ResponseEntity<DocenteResponseRest> consultarDocentes();
    ResponseEntity<DocenteResponseRest> consultarDocentesId(Long id);
    ResponseEntity<DocenteResponseRest> crear(Docentes docentes);
    ResponseEntity<DocenteResponseRest> actualizar(Docentes docentes, Long id);
    ResponseEntity<DocenteResponseRest> desactivarPorId(Long id);
    ResponseEntity<DocenteResponseRest> activarPorId(Long id);
}
