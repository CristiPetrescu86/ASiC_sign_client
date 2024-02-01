package ro.client_sign_app.clientapp.CSCLibrary;

import java.lang.reflect.Field;

public class Oauth2_token_req {
    private String code;
    private String grant_type;
    private String client_id;
    private String redirect_uri;
    private String client_secret;


    public Oauth2_token_req(String code) {
        this.code = code;
        this.grant_type = "authorization_code";
        this.client_id = "81ac496c-3ab8-4e9d-bbe3-cf8ccc37f65c";
        this.redirect_uri = "http://localhost:8080/";
        this.client_secret = "oHcz8PLVyRMJG1xgZbIDd3uiQEl75Wm2N0sKUO9TXqa";
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getGrant_type() {
        return grant_type;
    }

    public void setGrant_type(String grant_type) {
        this.grant_type = grant_type;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public String getRedirect_uri() {
        return redirect_uri;
    }

    public void setRedirect_uri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }

    public String getClient_secret() {
        return client_secret;
    }

    public void setClient_secret(String client_secret) {
        this.client_secret = client_secret;
    }

    public String returnBody(){
        return "code=" + this.code + "&grant_type=" + this.grant_type + "&client_id=" + this.client_id + "&redirect_uri=" + this.redirect_uri + "&client_secret=" + this.client_secret;
    }
}
