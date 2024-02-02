package ro.client_sign_app.clientapp.CSCLibrary;

import com.fasterxml.jackson.annotation.JsonSetter;

import java.util.ArrayList;
import java.util.List;

public class Cred_info_resp_cert {
    private String status;

    public String getStatus() {
        return status;
    }

    @JsonSetter("status")
    public void setStatus(String status) {
        this.status = status;
    }

    public List<String> getCertificates() {
        return certificates;
    }

    @JsonSetter("certificates")
    public void setCertificates(List<String> certificates) {
        this.certificates = certificates;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    @JsonSetter("issuerDN")
    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    @JsonSetter("serialNumber")
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    @JsonSetter("subjectDN")
    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getValidFrom() {
        return validFrom;
    }

    @JsonSetter("validFrom")
    public void setValidFrom(String validFrom) {
        this.validFrom = validFrom;
    }

    public String getValidTo() {
        return validTo;
    }

    @JsonSetter("validTo")
    public void setValidTo(String validTo) {
        this.validTo = validTo;
    }

    private List<String> certificates;
    private String issuerDN;
    private String serialNumber;
    private String subjectDN;
    private String validFrom;
    private String validTo;

    public Cred_info_resp_cert() {
        certificates = new ArrayList<>();
    }
}
