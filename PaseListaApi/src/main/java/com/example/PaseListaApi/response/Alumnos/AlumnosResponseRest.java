package com.example.PaseListaApi.response.Alumnos;

import com.example.PaseListaApi.model.Grupos;
import com.example.PaseListaApi.response.Grupos.GrupoResponseRest;
import com.example.PaseListaApi.response.ResponseRest;
import com.example.PaseListaApi.service.Alumnos.AlumnosServiceImpl;
import com.example.PaseListaApi.service.Alumnos.IAlumnosService;
import com.example.PaseListaApi.service.Grupos.GrupoServiceImpl;
import com.example.PaseListaApi.service.Grupos.IGruposService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

public class AlumnosResponseRest extends ResponseRest {
   private AlumnosResponse alumnosResponse = new AlumnosResponse();

   public AlumnosResponse getAlumnosResponse() {
       return alumnosResponse;
   }
   public void setAlumnosResponse(AlumnosResponse alumnosResponse) {
       this.alumnosResponse = alumnosResponse;
   }

}
