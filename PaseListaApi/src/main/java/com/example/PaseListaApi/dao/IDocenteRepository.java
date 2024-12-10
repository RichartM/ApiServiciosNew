package com.example.PaseListaApi.dao;

import com.example.PaseListaApi.model.Alumnos;
import com.example.PaseListaApi.model.Docentes;
import org.springframework.data.repository.CrudRepository;

public interface IDocenteRepository extends CrudRepository<Docentes, Long> {
}
