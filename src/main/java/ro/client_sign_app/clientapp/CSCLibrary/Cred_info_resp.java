package ro.client_sign_app.clientapp.CSCLibrary;

import com.fasterxml.jackson.annotation.JsonSetter;

// Deserializare cerere POST pentru raspunsul metodei credential/info
public class Cred_info_resp {
    private Cred_info_resp_key credinforespkey;
    private Cred_info_resp_cert credinforespcert;
    private String SCAL;
    private String description;
    private String authMode;
    private Integer multisign;

    public Cred_info_resp() {
        credinforespkey = new Cred_info_resp_key();
        credinforespcert = new Cred_info_resp_cert();
    }

    public Cred_info_resp_key getKey() {
        return credinforespkey;
    }

    @JsonSetter("key")
    public void setKey(Cred_info_resp_key credinforespkey) {
        this.credinforespkey = credinforespkey;
    }

    public Cred_info_resp_cert getCert() {
        return credinforespcert;
    }

    @JsonSetter("cert")
    public void setCert(Cred_info_resp_cert credinforespcert) {
        this.credinforespcert = credinforespcert;
    }

    public String getSCAL() {
        return SCAL;
    }

    @JsonSetter("SCAL")
    public void setSCAL(String SCAL) {
        this.SCAL = SCAL;
    }

    public String getDescription() {
        return description;
    }

    @JsonSetter("description")
    public void setDescription(String description) {
        this.description = description;
    }

    public String getAuthMode() {
        return authMode;
    }

    @JsonSetter("authMode")
    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public Integer getMultisign() {
        return multisign;
    }

    @JsonSetter("multisign")
    public void setMultisign(Integer multisign) {
        this.multisign = multisign;
    }
}

