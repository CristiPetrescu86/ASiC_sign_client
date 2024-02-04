package ro.client_sign_app.clientapp.CSCLibrary;

import com.fasterxml.jackson.annotation.JsonSetter;

import java.util.ArrayList;
import java.util.List;

public class sign_signHash_resp {
    private List<String> signatures;

    public List<String> getSignatures() {
        return signatures;
    }

    @JsonSetter("signatures")
    public void setSignatures(List<String> signatures) {
        this.signatures = signatures;
    }

    public sign_signHash_resp() {
        this.signatures = new ArrayList<>();
    }
}
