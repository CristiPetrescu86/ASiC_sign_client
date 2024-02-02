package ro.client_sign_app.clientapp.CSCLibrary;

public class Cred_info_req {
    private String credentialID;
    private String certificates;
    private boolean certInfo;
    private boolean authInfo;
    private String lang;

    public Cred_info_req(String credentialID, String certificates, boolean certInfo, boolean authInfo, String lang) {
        this.credentialID = credentialID;
        this.certificates = certificates;
        this.certInfo = certInfo;
        this.authInfo = authInfo;
        this.lang = lang;
    }

    public String getCredentialID() {
        return credentialID;
    }

    public void setCredentialID(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getCertificates() {
        return certificates;
    }

    public void setCertificates(String certificates) {
        this.certificates = certificates;
    }

    public boolean getCertInfo() {
        return certInfo;
    }

    public void setCertInfo(boolean certInfo) {
        this.certInfo = certInfo;
    }

    public boolean getAuthInfo() {
        return authInfo;
    }

    public void setAuthInfo(boolean authInfo) {
        this.authInfo = authInfo;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }
}
