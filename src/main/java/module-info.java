module ro.client_sign_app.clientapp {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;
    requires org.kordamp.bootstrapfx.core;
    requires jpms_dss_asic_cades;
    requires jpms_dss_enumerations;
    requires jpms_dss_model;
    requires jpms_dss_document;
    requires jpms_dss_asic_xades;
    requires jpms_dss_token;
    requires jpms_dss_asic_common;
    requires com.fasterxml.jackson.databind;
    requires jpms_dss_spi;
    requires jpms_dss_service;
    requires javafx.web;
    requires jpms_dss_pades;
    requires jpms_dss_pades_pdfbox;
    requires org.apache.pdfbox;
    requires java.desktop;

    exports ro.client_sign_app.clientapp;
    exports ro.client_sign_app.clientapp.Controller;
    opens ro.client_sign_app.clientapp.Controller to javafx.fxml;
    opens ro.client_sign_app.clientapp to javafx.fxml;
    exports ro.client_sign_app.clientapp.CSCLibrary to com.fasterxml.jackson.databind;
}