package com.example.PaseListaApi.response.Admin;


import com.example.PaseListaApi.model.Admin;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class AdminResponseRest {
    private Metadata metadata;
    private AdminResponse adminResponse;

    public AdminResponseRest() {
        this.metadata = new Metadata();
        this.adminResponse = new AdminResponse();
    }

    @Data
    public static class AdminResponse {
        private List<Admin> admins = new ArrayList<>();
    }

    @Data
    public static class Metadata {
        private String message;
        private String code;
        private String details;

        public Metadata() {
        }

        public Metadata(String message, String code, String details) {
            this.message = message;
            this.code = code;
            this.details = details;
        }
    }

    public void setMetada(String message, String code, String details) {
        this.metadata.setMessage(message);
        this.metadata.setCode(code);
        this.metadata.setDetails(details);
    }
}
