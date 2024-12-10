package com.example.PaseListaApi.model;

import jakarta.persistence.*;
@Entity
@Table(name = "materias")
public class Materia {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int idMateria;
    private String nombreMateria;
    private Boolean estado;

    public Materia() {
        this.estado = true;
    }
    public Materia(String nombreMateria, Grupos grupo) {
        this.nombreMateria = nombreMateria;

        this.estado = true;
    }

    public int getIdMateria() {
        return idMateria;
    }

    public void setIdMateria(int idMateria) {
        this.idMateria = idMateria;
    }

    public String getNombreMateria() {
        return nombreMateria;
    }

    public void setNombreMateria(String nombreMateria) {
        this.nombreMateria = nombreMateria;
    }


    public Boolean getEstado() {
        return estado;
    }

    public void setEstado(Boolean estado) {
        this.estado = estado;
    }
}
