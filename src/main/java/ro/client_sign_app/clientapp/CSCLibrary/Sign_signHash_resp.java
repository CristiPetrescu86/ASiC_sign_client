package ro.client_sign_app.clientapp.CSCLibrary;

import com.fasterxml.jackson.annotation.JsonSetter;

import java.util.ArrayList;
import java.util.List;

// Deserializare cerere POST pentru raspunsul metodei signatures/signHash
public class Sign_signHash_resp {
    private List<String> signatures;

    public List<String> getSignatures() {
        return signatures;
    }

    @JsonSetter("signatures")
    public void setSignatures(List<String> signatures) {
        this.signatures = signatures;
    }

    public Sign_signHash_resp() {
        this.signatures = new ArrayList<>();
    }
}
