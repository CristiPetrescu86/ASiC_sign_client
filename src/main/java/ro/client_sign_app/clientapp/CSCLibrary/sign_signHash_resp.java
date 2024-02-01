package ro.client_sign_app.clientapp.CSCLibrary;

import java.util.List;

public class sign_signHash_resp {
    private List<String> signatures;

    public List<String> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<String> signatures) {
        this.signatures = signatures;
    }

    public sign_signHash_resp(List<String> signatures) {
        this.signatures = signatures;
    }
}
