package com.example.PaseListaApi.response.Docente;

import com.example.PaseListaApi.model.Alumnos;
import com.example.PaseListaApi.model.Docentes;
import com.example.PaseListaApi.response.ResponseRest;

import java.util.List;

public class DocenteResponse  {
    private List<Docentes> docentes;
    public List<Docentes> getDocentes() {
        return docentes;
    }
    public void setDocentes(List<Docentes> docentes) {
        this.docentes = docentes;
    }
}
