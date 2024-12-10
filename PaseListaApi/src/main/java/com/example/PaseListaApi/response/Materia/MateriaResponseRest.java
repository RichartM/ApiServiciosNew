package com.example.PaseListaApi.response.Materia;

import com.example.PaseListaApi.model.Materia;
import com.example.PaseListaApi.response.Grupos.GrupoResponse;
import com.example.PaseListaApi.response.ResponseRest;

public class MateriaResponseRest extends ResponseRest {
    private MateriaResponse materiaResponse = new MateriaResponse();

    public MateriaResponse getMateriaResponse(){
        return  materiaResponse;
    }

    public void setMateriaResponse(MateriaResponse materiaResponse){
        this.materiaResponse = materiaResponse;
    }
}
