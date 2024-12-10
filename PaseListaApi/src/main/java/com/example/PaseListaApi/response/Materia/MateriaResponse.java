package com.example.PaseListaApi.response.Materia;

import com.example.PaseListaApi.model.Grupos;
import com.example.PaseListaApi.model.Materia;

import java.util.List;

public class MateriaResponse {
    private List<Materia> materias;
    public List<Materia> getMaterias() {
        return materias;
    }
    public void setMaterias(List<Materia> materias) {
        this.materias = materias;
    }
}
