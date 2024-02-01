package ro.client_sign_app.clientapp.CSCLibrary;

import java.util.List;

public class Sign_signHash_req {
    private String credentialID;
    private List<String> hash;
    private String signAlgo;
    private String sad;

    public Sign_signHash_req(String credentialID, List<String> hash, String signAlgo, String sad) {
        this.credentialID = credentialID;
        this.hash = hash;
        this.signAlgo = signAlgo;
        this.sad = sad;
    }

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public List<String> getHash() {
        return hash;
    }

    public void setHash(List<String> hash) {
        this.hash = hash;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public void setSignAlgo(String signAlgo) {
        this.signAlgo = signAlgo;
    }

    public String getSad() {
        return sad;
    }

    public void setSad(String sad) {
        this.sad = sad;
    }
}
