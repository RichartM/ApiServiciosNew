package com.example.PaseListaApi.service.Grupos;

import com.example.PaseListaApi.model.Grupos;
import com.example.PaseListaApi.response.Grupos.GrupoResponseRest;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;

public interface IGruposService {
    //CONSULTA GRUPO POR ID
    @Transactional(readOnly = true)
    ResponseEntity<GrupoResponseRest> consultarGrupoId(Long id);
    public ResponseEntity<GrupoResponseRest> crear(Grupos grupos);
    public ResponseEntity<GrupoResponseRest> consultarGrupos();
    public ResponseEntity<GrupoResponseRest> actualizarGrupos(Grupos grupos, Long id);
    ResponseEntity<GrupoResponseRest> desactivarPorId(Long id);
    ResponseEntity<GrupoResponseRest> activarPorId(Long id);

}
