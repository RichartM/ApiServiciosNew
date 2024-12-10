package com.example.PaseListaApi.dao;

import com.example.PaseListaApi.model.Materia;
import org.springframework.data.repository.CrudRepository;

public interface IMateriaRepository extends CrudRepository<Materia, Long> {
}
