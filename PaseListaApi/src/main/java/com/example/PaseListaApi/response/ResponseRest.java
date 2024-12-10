package com.example.PaseListaApi.response;


import java.util.ArrayList;
//Libreria tipo array o matriz
import java.util.HashMap;

public class ResponseRest {
    private ArrayList<HashMap<String, String>> metadata = new ArrayList<>();

    public ArrayList<HashMap<String, String>> getMetadata() {
        return metadata;
    }
    public void setMetada(String tipo, String codigo, String date) {
        HashMap<String, String> mapa = new HashMap<>();

        mapa.put("tipo", tipo);
        mapa.put("codigo", codigo);
        mapa.put("date", date);

        metadata.add(mapa);
    }
}
