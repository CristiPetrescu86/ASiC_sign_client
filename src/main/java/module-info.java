module ro.client_sign_app.clientapp {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;
    requires org.kordamp.bootstrapfx.core;

    exports ro.client_sign_app.clientapp;
    exports ro.client_sign_app.clientapp.Controller;
    opens ro.client_sign_app.clientapp.Controller to javafx.fxml;
    opens ro.client_sign_app.clientapp to javafx.fxml;
}