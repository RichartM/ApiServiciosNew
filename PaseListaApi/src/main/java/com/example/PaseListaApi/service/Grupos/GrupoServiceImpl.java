package com.example.PaseListaApi.service.Grupos;

import com.example.PaseListaApi.dao.IGrupoRepository;
import com.example.PaseListaApi.model.Grupos;
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
//Logica de negocio

@Service
public class GrupoServiceImpl implements IGruposService {
    private static final Logger log = LoggerFactory.getLogger(GrupoServiceImpl.class);
    @Autowired
    private IGrupoRepository gruposDAO;


    //CONSULTA * GRUPOS
    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<GrupoResponseRest> consultarGrupos() {
        log.info("Buscando grupos");
        GrupoResponseRest response = new GrupoResponseRest();
        try {
            List<Grupos> grupos = (List<Grupos>) gruposDAO.findAll();
            response.getGrupoResponse().setGrupos(grupos);
            response.setMetada("Respuesta OK", "00", "Respuesta exitosaaaa");
        } catch (Exception e) {
            response.setMetada("Error", "-1", "Error al buscar categoria");
            log.error("Error al guardar categorias", e.getMessage());
            e.getStackTrace();
            return new ResponseEntity<GrupoResponseRest>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<GrupoResponseRest>(response, HttpStatus.OK);
    }

    @Override
    @Transactional
    public ResponseEntity<GrupoResponseRest> actualizarGrupos(Grupos grupos, Long id) {
        log.info("ACctualizar grupos");
        GrupoResponseRest response = new GrupoResponseRest();
        List<Grupos> list = new ArrayList<>();
        try {
            Optional<Grupos> grupoBuscado = gruposDAO.findById(id);
            if (grupoBuscado.isPresent()) {
                grupoBuscado.get().setGrado(grupos.getGrado());
                grupoBuscado.get().setGrupo(grupos.getGrupo());
                grupoBuscado.get().setCarrera(grupos.getCarrera());
                grupoBuscado.get().setEstado(grupos.getEstado());
                Grupos grupoActualizar = gruposDAO.save(grupoBuscado.get());
                if (grupoActualizar != null) {
                    list.add(grupoActualizar);
                    response.getGrupoResponse().setGrupos(list);
                    response.setMetada("Respuesta OK", "00", "Respuesta exitosaaaa");
                } else {
                    log.info("No se encontro el GRUPO");
                    response.setMetada("Respuesta no encontrada", "-1", "Respuesta no localizada");
                    return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
                }
            } else {
                log.info("No se enccontro el grupo");
                response.setMetada("Respuesta no encontrada", "-1", "Grupo no localizada");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
        }catch (Exception e){
            log.info("Error al actualizar grupos");
            response.setMetada("Error", "-1", "Error al actualizar grupos");
            e.getStackTrace();
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }


    //CONSULTA GRUPO POR ID
    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<GrupoResponseRest> consultarGrupoId(Long id) {
        log.info("Buscando grupo con id {}");
        GrupoResponseRest response = new GrupoResponseRest();
        List<Grupos> list = new ArrayList<>();

        try {
            Optional<Grupos> grupo = gruposDAO.findById(id);
            if (grupo.isPresent()) {
                list.add(grupo.get());
                response.getGrupoResponse().setGrupos(list);
                response.setMetada("Respuesta OK", "00", "Respuesta exitosaaaa");
            } else {
                log.error("Error al buscar grupo", id);
                response.setMetada("Error", "-1", "Error al buscar categoria");
                return new ResponseEntity<GrupoResponseRest>(response, HttpStatus.NOT_FOUND);
            }
        }catch (Exception e){
            response.setMetada("Error", "-1", "Error al buscar categoria");
            log.error("Error al guardar categorias", e.getMessage());
            e.getStackTrace();
            return new ResponseEntity<GrupoResponseRest>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<GrupoResponseRest>(response, HttpStatus.OK);
    }


    //CREAMOS GRUPOS
    @Override
    @Transactional
    public ResponseEntity<GrupoResponseRest> crear(Grupos grupos) {
        log.info("Inicio del método crear por Grupos");
        GrupoResponseRest response = new GrupoResponseRest();
        List<Grupos> list = new ArrayList<>();
        try {
            grupos.setEstado(true);

            Grupos gruposGuardar = gruposDAO.save(grupos);
            if (gruposGuardar != null) {
                list.add(gruposGuardar);
                response.getGrupoResponse().setGrupos(list);
                response.setMetada("Respuesta OK", "00", "CREACIÓN exitosa");
            } else {
                log.info("No se encontró la categoría");
                response.setMetada("Respuesta no encontrada", "-1", "Categoría no creada");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
        } catch (Exception e) {
            response.setMetada("Error", "-1", "Error al crear categoría");
            log.error("Error al guardar categoría", e);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<GrupoResponseRest> desactivarPorId(Long id) {
        log.info("Inicio del método desactivarPorId para el grupo con id: " + id);
        GrupoResponseRest response = new GrupoResponseRest();
        try {
            Optional<Grupos> grupoOptional = gruposDAO.findById(id);

            if (grupoOptional.isPresent()) {
                Grupos grupo = grupoOptional.get();
                grupo.setEstado(false);
                gruposDAO.save(grupo);

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
    public ResponseEntity<GrupoResponseRest> activarPorId(Long id) {
        log.info("Inicio del método activarPorId para el grupo con id: " + id);
        GrupoResponseRest response = new GrupoResponseRest();
        try {
            Optional<Grupos> grupoOptional = gruposDAO.findById(id);

            if (grupoOptional.isPresent()) {
                Grupos grupo = grupoOptional.get();
                grupo.setEstado(true);
                gruposDAO.save(grupo);

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

