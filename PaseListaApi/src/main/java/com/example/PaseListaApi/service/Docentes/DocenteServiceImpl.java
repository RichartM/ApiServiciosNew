package com.example.PaseListaApi.service.Docentes;

import com.example.PaseListaApi.dao.IAlumnosRepository;
import com.example.PaseListaApi.dao.IDocenteRepository;
import com.example.PaseListaApi.model.Alumnos;
import com.example.PaseListaApi.model.Docentes;
import com.example.PaseListaApi.model.Grupos;
import com.example.PaseListaApi.model.Materia;
import com.example.PaseListaApi.model.user_info.User_infoRepository;
import com.example.PaseListaApi.model.user_info.Users_info;
import com.example.PaseListaApi.response.Alumnos.AlumnosResponseRest;
import com.example.PaseListaApi.response.Docente.DocenteResponseRest;
import com.example.PaseListaApi.response.Grupos.GrupoResponseRest;
import com.example.PaseListaApi.response.Materia.MateriaResponseRest;
import com.example.PaseListaApi.service.Alumnos.AlumnosServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class DocenteServiceImpl implements IDocenteService {
    private static final Logger log = LoggerFactory.getLogger(DocenteServiceImpl.class);
    @Autowired
    private IDocenteRepository docentesDAO;

    @Autowired
    private User_infoRepository userInfoRepository;

    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<DocenteResponseRest> consultarDocentes() {
        log.info("Byuscando Docentes");
        DocenteResponseRest response = new DocenteResponseRest();
        try {
            List<Docentes> docentesList = (List<Docentes>) docentesDAO.findAll();
            response.getDocenteResponse().setDocentes(docentesList);
            response.setMetada("Respuesta ok", "00", "Respuesta exitosa");
        } catch (Exception e) {
            response.setMetada("Error al consultar alumnos", "00", "Error: " + e.getMessage());
            log.error("Ettor al buscar categorias", e.getMessage());
            e.getStackTrace();
            return new ResponseEntity<DocenteResponseRest>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<DocenteResponseRest>(response, HttpStatus.OK);
    }

    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<DocenteResponseRest> consultarDocentesId(Long id) {
        log.info("Buscando alumno por id");
        DocenteResponseRest docenteResponse = new DocenteResponseRest();
        List<Docentes> list = new ArrayList<>();

        try {
            Optional<Docentes> docentes = docentesDAO.findById(id);
            if (docentes.isPresent()) {
                list.add(docentes.get());
                docenteResponse.getDocenteResponse().setDocentes(list);
                docenteResponse.setMetada("Respuesta OK", "00", "Respuesta exitosaaaa");
            } else {
                log.error("Error al buscar alumno");
                docenteResponse.setMetada("Error", "-1", "Error al buscar Alumno por ID");
                return new ResponseEntity<DocenteResponseRest>(docenteResponse, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            docenteResponse.setMetada("Error", "-1", "Error al buscar alumno");
            log.error("Error al buscar por id");
            e.getStackTrace();
            return new ResponseEntity<DocenteResponseRest>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<DocenteResponseRest>(docenteResponse, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<DocenteResponseRest> crear(Docentes docentes) {
        log.info("Creacion de alumno");
        DocenteResponseRest response = new DocenteResponseRest();
        List<Docentes> listaDocente = new ArrayList<>();
        try {
            BCryptPasswordEncoder passwordEncoder =new BCryptPasswordEncoder();
            docentes.setPassword(passwordEncoder.encode(docentes.getPassword()));
            Users_info newUSer = new Users_info(null,docentes.getCorreo(), docentes.getPassword(), "Docente");
            this.userInfoRepository.save(newUSer);
            Docentes docentesGuardar = docentesDAO.save(docentes);
            if (docentesGuardar != null) {
                listaDocente.add(docentesGuardar);
                response.getDocenteResponse().setDocentes(listaDocente);
                response.setMetada("Respuesta OK", "00", "CREACION EXITOSA");
            } else {
                log.info("No se agrego el alumno");
                response.setMetada("No se agrego el alumno", "-1", "Alumno creado");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            response.setMetada("Error", "-1", "Error al crear alumno");
            log.info("No se puedp crear alumno");
            return new ResponseEntity<DocenteResponseRest>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<DocenteResponseRest> actualizar(Docentes docentes, Long id) {
        log.info("Actualizando docente con id: {}", id);
        DocenteResponseRest response = new DocenteResponseRest();
        List<Docentes> list = new ArrayList<>();
        try {
            Optional<Docentes> docenteExistente = docentesDAO.findById(id);
            if (docenteExistente.isPresent()) {

                docenteExistente.get().setPrimerNombre(docentes.getPrimerNombre());
                docenteExistente.get().setSegundoNombre(docentes.getSegundoNombre());
                docenteExistente.get().setPrimerApellido(docentes.getPrimerApellido());
                docenteExistente.get().setSegundoApellido(docentes.getSegundoApellido());
                docenteExistente.get().setCorreo(docentes.getCorreo());
                docenteExistente.get().setPassword(docentes.getPassword());
                docenteExistente.get().setSexo(docentes.getSexo());
                docenteExistente.get().setGrupos(docentes.getGrupos());
                docenteExistente.get().setMaterias(docentes.getMaterias());
                Docentes docenteActualizado = docentesDAO.save(docenteExistente.get());
                list.add(docenteActualizado);
                response.getDocenteResponse().setDocentes(list);
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

    public ResponseEntity<DocenteResponseRest> desactivarPorId(Long id) {
        log.info("Inicio del método desactivarPorId para el grupo con id: " + id);
        DocenteResponseRest response = new DocenteResponseRest();
        try {
            Optional<Docentes> docentesOptional = docentesDAO.findById(id);

            if (docentesOptional.isPresent()) {
                Docentes docentes = docentesOptional.get();
                docentes.setEstado(false);
                docentesDAO.save(docentes);

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
    public ResponseEntity<DocenteResponseRest> activarPorId(Long id) {
        log.info("Inicio del método activarPorId para el grupo con id: " + id);
        DocenteResponseRest response = new DocenteResponseRest();
        try {
            Optional<Docentes> docentesOptional = docentesDAO.findById(id);

            if (docentesOptional.isPresent()) {
                Docentes docentes = docentesOptional.get();
                docentes.setEstado(true);
                docentesDAO.save(docentes);

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
