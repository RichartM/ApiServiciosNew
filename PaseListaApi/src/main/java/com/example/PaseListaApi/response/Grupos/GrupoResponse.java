package com.example.PaseListaApi.response.Grupos;

import com.example.PaseListaApi.model.Grupos;

import java.util.List;

public class GrupoResponse {
    private List<Grupos> grupos;
    public List<Grupos> getGrupos() {
        return grupos;
    }
    public void setGrupos(List<Grupos> grupos) {
        this.grupos = grupos;
    }
}
