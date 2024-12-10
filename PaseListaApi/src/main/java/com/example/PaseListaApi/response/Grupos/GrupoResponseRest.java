package com.example.PaseListaApi.response.Grupos;

import com.example.PaseListaApi.response.ResponseRest;

public class GrupoResponseRest extends ResponseRest {
    private GrupoResponse grupoResponse = new GrupoResponse();

public GrupoResponse getGrupoResponse(){
return  grupoResponse;
}

public void setGrupoResponse(GrupoResponse grupoResponse){
this.grupoResponse = grupoResponse;
}

}
