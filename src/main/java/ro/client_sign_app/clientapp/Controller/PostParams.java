package ro.client_sign_app.clientapp.Controller;

public class PostParams {
    private String credID;
    private String signAlgo;
    private String digestAlgo;
    private String hashToBeSigned;


    public String getCredID() {
        return credID;
    }

    public void setCredID(String credID) {
        this.credID = credID;
    }

    public String getSignAlgo() {
        return signAlgo;
    }

    public void setSignAlgo(String signAlgo) {
        this.signAlgo = signAlgo;
    }

    public String getDigestAlgo() {
        return digestAlgo;
    }

    public void setDigestAlgo(String digestAlgo) {
        this.digestAlgo = digestAlgo;
    }

    public String getHashToBeSigned() {
        return hashToBeSigned;
    }

    public void setHashToBeSigned(String hashToBeSigned) {
        this.hashToBeSigned = hashToBeSigned;
    }
}
