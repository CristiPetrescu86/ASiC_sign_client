module ro.client_sign_app.clientapp {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;
    requires org.kordamp.bootstrapfx.core;

    opens ro.client_sign_app.clientapp to javafx.fxml;
    exports ro.client_sign_app.clientapp;
}