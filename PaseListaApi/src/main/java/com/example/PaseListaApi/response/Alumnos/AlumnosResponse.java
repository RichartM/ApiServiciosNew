package com.example.PaseListaApi.response.Alumnos;

import com.example.PaseListaApi.model.Alumnos;
import com.example.PaseListaApi.model.Grupos;
import com.example.PaseListaApi.model.Materia;

import java.util.List;

public class AlumnosResponse {
    private List<Alumnos> alumnos;
    public List<Alumnos> getAlumnos() {
        return alumnos;
    }
    public void setAlumnos(List<Alumnos> alumnos) {
        this.alumnos = alumnos;
    }
}
