package ro.client_sign_app.clientapp.CSCLibrary;

import com.fasterxml.jackson.annotation.JsonSetter;

import java.util.ArrayList;
import java.util.List;
// Deserializare cerere POST pentru raspunsul metodei credential/info
public class Cred_info_resp_key {
    public Cred_info_resp_key() {
        algo = new ArrayList<>();
    }

    public String getStatus() {
        return status;
    }

    @JsonSetter("status")
    public void setStatus(String status) {
        this.status = status;
    }

    public Integer getLen() {
        return len;
    }

    @JsonSetter("len")
    public void setLen(Integer len) {
        this.len = len;
    }

    public List<String> getAlgo() {
        return algo;
    }

    @JsonSetter("algo")
    public void setAlgo(List<String> algo) {
        this.algo = algo;
    }

    private String status;
    private Integer len;
    private List<String> algo;
}
