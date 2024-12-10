package com.example.PaseListaApi.service.Materia;

import com.example.PaseListaApi.dao.IMateriaRepository;
import com.example.PaseListaApi.model.Materia;
import com.example.PaseListaApi.response.Materia.MateriaResponseRest;
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
public class MateriaServiceImpl implements IMateriaService {
    private static final Logger log = LoggerFactory.getLogger(MateriaServiceImpl.class);

    @Autowired
    private IMateriaRepository materiaDAO;

    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<MateriaResponseRest> buscarMaterias() {
        log.info("Buscando todas las materias");
        MateriaResponseRest response = new MateriaResponseRest();
        try {
            List<Materia> materias = (List<Materia>) materiaDAO.findAll();
            response.getMateriaResponse().setMaterias(materias);
            response.setMetada("Respuesta OK", "00", "Consulta exitosa");
        } catch (Exception e) {
            log.error("Error al buscar materias", e);
            response.setMetada("Error", "-1", "Error al buscar materias");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<MateriaResponseRest> buscarMateriaPorId(Long id) {
        log.info("Buscando materia con id: {}", id);
        MateriaResponseRest response = new MateriaResponseRest();
        List<Materia> list = new ArrayList<>();
        try {
            Optional<Materia> materia = materiaDAO.findById(id);
            if (materia.isPresent()) {
                list.add(materia.get());
                response.getMateriaResponse().setMaterias(list);
                response.setMetada("Respuesta OK", "00", "Consulta exitosa");
            } else {
                response.setMetada("No encontrado", "-1", "Materia no encontrada");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            log.error("Error al buscar materia", e);
            response.setMetada("Error", "-1", "Error al buscar materia");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    @Transactional
    public ResponseEntity<MateriaResponseRest> crearMateria(Materia materia) {
        log.info("Creando una nueva materia");
        MateriaResponseRest response = new MateriaResponseRest();
        List<Materia> list = new ArrayList<>();
        try {
            materia.setEstado(true);  // Suponiendo que deseas inicializar el estado como activo
            Materia materiaGuardada = materiaDAO.save(materia);
            list.add(materiaGuardada);
            response.getMateriaResponse().setMaterias(list);
            response.setMetada("Respuesta OK", "00", "Creación exitosa");
        } catch (Exception e) {
            log.error("Error al crear materia", e);
            response.setMetada("Error", "-1", "Error al crear materia");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    @Transactional
    public ResponseEntity<MateriaResponseRest> actualizarMateria(Materia materia, Long id) {
        log.info("Actualizando materia con id: {}", id);
        MateriaResponseRest response = new MateriaResponseRest();
        List<Materia> list = new ArrayList<>();
        try {
            Optional<Materia> materiaExistente = materiaDAO.findById(id);
            if (materiaExistente.isPresent()) {
                materiaExistente.get().setNombreMateria(materia.getNombreMateria());
                Materia materiaActualizada = materiaDAO.save(materiaExistente.get());
                list.add(materiaActualizada);
                response.getMateriaResponse().setMaterias(list);
                response.setMetada("Respuesta OK", "00", "Actualización exitosa");
            } else {
                response.setMetada("No encontrado", "-1", "Materia no encontrada");
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
    public ResponseEntity<MateriaResponseRest> desactivarMateriaPorId(Long id) {
        log.info("Desactivando materia con id: {}", id);
        MateriaResponseRest response = new MateriaResponseRest();
        try {
            Optional<Materia> materia = materiaDAO.findById(id);
            if (materia.isPresent()) {
                materia.get().setEstado(false);
                materiaDAO.save(materia.get());
                response.setMetada("Respuesta OK", "00", "Materia desactivada");
            } else {
                response.setMetada("No encontrado", "-1", "Materia no encontrada");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            log.error("Error al desactivar materia", e);
            response.setMetada("Error", "-1", "Error al desactivar materia");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<MateriaResponseRest> activarMateriaPorId(Long id) {
        log.info("Activando materia con id: {}", id);
        MateriaResponseRest response = new MateriaResponseRest();
        try {
            Optional<Materia> materia = materiaDAO.findById(id);
            if (materia.isPresent()) {
                materia.get().setEstado(true);
                materiaDAO.save(materia.get());
                response.setMetada("Respuesta OK", "00", "Materia activada");
            } else {
                response.setMetada("No encontrado", "-1", "Materia no encontrada");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            log.error("Error al activar materia", e);
            response.setMetada("Error", "-1", "Error al activar materia");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
