package com.example.PaseListaApi.response.Docente;

import com.example.PaseListaApi.response.Alumnos.AlumnosResponse;
import com.example.PaseListaApi.response.ResponseRest;

public class DocenteResponseRest extends ResponseRest {
    private DocenteResponse docenteResponse = new DocenteResponse();

    public DocenteResponse getDocenteResponse() {
        return docenteResponse;
    }
    public void setDocenteResponse(DocenteResponse docenteResponse) {
        this.docenteResponse = docenteResponse;
    }
}
