package com.example.PaseListaApi.service.Alumnos;

import com.example.PaseListaApi.model.Alumnos;
import com.example.PaseListaApi.response.Alumnos.AlumnosResponseRest;
import com.example.PaseListaApi.response.Docente.DocenteResponseRest;
import org.springframework.http.ResponseEntity;

public interface IAlumnosService {
    ResponseEntity<AlumnosResponseRest> consultarAlumnos();
    ResponseEntity<AlumnosResponseRest> consultarAlumnosId(Long id);
    ResponseEntity<AlumnosResponseRest> crear(Alumnos alumnos);
    ResponseEntity<AlumnosResponseRest> actualizar(Alumnos alumnos, Long id);
    ResponseEntity<AlumnosResponseRest> desactivarPorId(Long id);
    ResponseEntity<AlumnosResponseRest> activarPorId(Long id);
}
