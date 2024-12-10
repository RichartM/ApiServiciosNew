package com.example.PaseListaApi.service.Alumnos;

import com.example.PaseListaApi.dao.IAlumnosRepository;
import com.example.PaseListaApi.model.Alumnos;
import com.example.PaseListaApi.model.Docentes;
import com.example.PaseListaApi.model.Grupos;
import com.example.PaseListaApi.response.Alumnos.AlumnosResponseRest;
import com.example.PaseListaApi.response.Docente.DocenteResponseRest;
import com.example.PaseListaApi.response.Grupos.GrupoResponseRest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class AlumnosServiceImpl implements  IAlumnosService {
    private static final Logger log = LoggerFactory.getLogger(AlumnosServiceImpl.class);
    @Autowired
    private IAlumnosRepository alumnosDAO;

    @Transactional(readOnly = true)
    public ResponseEntity<AlumnosResponseRest> consultarAlumnos() {
        log.info("Byuscando alumnos");
        AlumnosResponseRest response = new AlumnosResponseRest();
        try {
            List<Alumnos> alumnosList = (List<Alumnos>) alumnosDAO.findAll();
            response.getAlumnosResponse().setAlumnos(alumnosList);
            response.setMetada("Respuesta ok", "00", "Respuesta exitosa");
        } catch (Exception e) {
            response.setMetada("Error al consultar alumnos", "00", "Error: " + e.getMessage());
            log.error("Ettor al buscar categorias", e.getMessage());
            e.getStackTrace();
            return new ResponseEntity<AlumnosResponseRest>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<AlumnosResponseRest>(response, HttpStatus.OK);
    }

    @Override
    @Transactional
    public ResponseEntity<AlumnosResponseRest> consultarAlumnosId(Long id) {
        log.info("Buscando alumno por id");
        AlumnosResponseRest alumnosResponse = new AlumnosResponseRest();
        List<Alumnos> list = new ArrayList<>();

        try {
            Optional<Alumnos> alumnos = alumnosDAO.findById(id);
            if (alumnos.isPresent()) {
                list.add(alumnos.get());
                alumnosResponse.getAlumnosResponse().setAlumnos(list);
                alumnosResponse.setMetada("Respuesta OK", "00", "Respuesta exitosaaaa");
            } else {
                log.error("Error al buscar alumno");
                alumnosResponse.setMetada("Error", "-1", "Error al buscar Alumno por ID");
                return new ResponseEntity<AlumnosResponseRest>(alumnosResponse, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            alumnosResponse.setMetada("Error", "-1", "Error al buscar alumno");
            log.error("Error al buscar por id");
            e.getStackTrace();
            return new ResponseEntity<AlumnosResponseRest>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<AlumnosResponseRest>(alumnosResponse, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<AlumnosResponseRest> crear(Alumnos alumnos) {
        log.info("Creacion de alumno");
        AlumnosResponseRest response = new AlumnosResponseRest();
        List<Alumnos> listaAlumno = new ArrayList<>();
        try {


            Alumnos alumnosGuardar = alumnosDAO.save(alumnos);
            if (alumnosGuardar != null) {
                listaAlumno.add(alumnosGuardar);
                response.getAlumnosResponse().setAlumnos(listaAlumno);
                response.setMetada("Respuesta OK", "00", "CREACION EXITOSA");
            } else {
                log.info("No se agrego el alumno");
                response.setMetada("No se agrego el alumno", "-1", "Alumno creado");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            response.setMetada("Error", "-1", "Error al crear alumno");
            log.info("No se puedp crear alumno");
            return new ResponseEntity<AlumnosResponseRest>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<AlumnosResponseRest> actualizar(Alumnos alumnos, Long id) {
        log.info("Actualizando docente con id: {}", id);
        AlumnosResponseRest response = new AlumnosResponseRest();
        List<Alumnos> list = new ArrayList<>();
        try {
            Optional<Alumnos> alumnoExistente = alumnosDAO.findById(id);
            if (alumnoExistente.isPresent()) {

                alumnoExistente.get().setPrimerNombre(alumnos.getPrimerNombre());
                alumnoExistente.get().setSegundoNombre(alumnos.getSegundoNombre());
                alumnoExistente.get().setPrimerApellido(alumnos.getPrimerApellido());
                alumnoExistente.get().setSegundoApellido(alumnos.getSegundoApellido());
                alumnoExistente.get().setCorreo(alumnos.getCorreo());
                alumnoExistente.get().setPassword(alumnos.getPassword());
                alumnoExistente.get().setSexo(alumnos.getSexo());
                alumnoExistente.get().setGrupos(alumnos.getGrupos());
                alumnoExistente.get().setFoto(alumnos.getFoto());
                alumnoExistente.get().setEstado(alumnos.isEstado());
                Alumnos alumnoActualizado = alumnosDAO.save(alumnoExistente.get());
                list.add(alumnoActualizado);
                response.getAlumnosResponse().setAlumnos(list);
                response.setMetada("Respuesta OK", "00", "Actualización exitosa");

            } else {
                response.setMetada("No encontrado", "-1", "docente no encontrada");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            log.error("Error al actualizar materia", e);
            response.setMetada("Error", "-1", "Error al actualizar materia");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<AlumnosResponseRest> desactivarPorId(Long id) {
        log.info("Inicio del método desactivarPorId para el grupo con id: " + id);
        AlumnosResponseRest response = new AlumnosResponseRest();
        try {
            Optional<Alumnos> alumnosOptional = alumnosDAO.findById(id);

            if (alumnosOptional.isPresent()) {
                Alumnos alumno = alumnosOptional.get();
                alumno.setEstado(false);
                alumnosDAO.save(alumno);

                response.setMetada("Respuesta OK", "00", "Estado del grupo actualizado a Inactivo");
            } else {
                log.info("No se encontró el grupo con el ID: " + id);
                response.setMetada("No encontrado", "-1", "Grupo no encontrado con el ID proporcionado");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            response.setMetada("Error", "-1", "Error al desactivar el grupo");
            log.error("Error al desactivar el grupo", e);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<AlumnosResponseRest> activarPorId(Long id) {
        log.info("Inicio del método activarPorId para el grupo con id: " + id);
        AlumnosResponseRest response = new AlumnosResponseRest();
        try {
            Optional<Alumnos> alumnosOptional = alumnosDAO.findById(id);

            if (alumnosOptional.isPresent()) {
                Alumnos alumnos = alumnosOptional.get();
                alumnos.setEstado(true);
                alumnosDAO.save(alumnos);

                response.setMetada("Respuesta OK", "00", "Estado del grupo actualizado a Activo");
            } else {
                log.info("No se encontró el grupo con el ID: " + id);
                response.setMetada("No encontrado", "-1", "Grupo no encontrado con el ID proporcionado");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            response.setMetada("Error", "-1", "Error al activar el grupo");
            log.error("Error al activar el grupo", e);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}