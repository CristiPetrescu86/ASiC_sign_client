package ro.client_sign_app.clientapp.CSCLibrary;

import com.fasterxml.jackson.annotation.JsonSetter;

import java.util.ArrayList;
import java.util.List;

// Deserializare cerere POST pentru raspunsul metodei credential/list
public class Cred_list_resp {
    public List<String> getCredentials() {
        return credentialIDs;
    }

    @JsonSetter("credentialIDs")
    public void setCredentials(List<String> credentials) {
        this.credentialIDs = credentials;
    }

    private List<String> credentialIDs;

    public Cred_list_resp() {
        credentialIDs = new ArrayList<>();
    }
}
