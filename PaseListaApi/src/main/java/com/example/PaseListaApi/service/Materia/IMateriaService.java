package com.example.PaseListaApi.service.Materia;

import com.example.PaseListaApi.model.Materia;
import com.example.PaseListaApi.response.Grupos.GrupoResponseRest;
import com.example.PaseListaApi.response.Materia.MateriaResponseRest;
import jakarta.transaction.Transactional;
import org.springframework.http.ResponseEntity;

public interface IMateriaService {
    public ResponseEntity<MateriaResponseRest> buscarMaterias();
    ResponseEntity<MateriaResponseRest> buscarMateriaPorId(Long id);
    ResponseEntity<MateriaResponseRest> crearMateria(Materia materia);
    ResponseEntity<MateriaResponseRest> actualizarMateria(Materia materia, Long id);
    ResponseEntity<MateriaResponseRest> desactivarMateriaPorId(Long id);
    ResponseEntity<MateriaResponseRest> activarMateriaPorId(Long id);

}
