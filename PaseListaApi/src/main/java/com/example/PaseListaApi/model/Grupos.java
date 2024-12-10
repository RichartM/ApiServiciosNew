package com.example.PaseListaApi.model;

import jakarta.persistence.*;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
@Table(name = "grupos")
public class Grupos {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id_grupo;

    private int grado;
    private char grupo;
    private String carrera;

    //public String getIdGrupoConNomenclatura() {
      //  return "GRUPO-" + id_grupo;
    // }

    //Delete logico
    private Boolean estado;
    public Boolean getEstado() {
        return estado;
    }

    public void setEstado(Boolean activo) {
        this.estado = activo;
    }


    public long getId_grupo() {
        return id_grupo;
    }

    public void setId_grupo(int id_grupo) {
        this.id_grupo = id_grupo;
    }

    public int getGrado() {
        return grado;
    }

    public void setGrado(int grado) {
        this.grado = grado;
    }

    public char getGrupo() {
        return grupo;
    }

    public void setGrupo(char grupo) {
        this.grupo = grupo;
    }

    public String getCarrera() {
        return carrera;
    }

    public void setCarrera(String carrera) {
        this.carrera = carrera;
    }
}
