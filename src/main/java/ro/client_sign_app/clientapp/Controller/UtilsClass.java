package ro.client_sign_app.clientapp.Controller;

import javafx.scene.control.Alert;

import java.util.Base64;

public class UtilsClass {
    public static void infoBox(String infoMessage, String titleBar, String headerMessage)
    {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(titleBar);
        alert.setHeaderText(headerMessage);
        alert.setContentText(infoMessage);
        alert.showAndWait();
    }
    public static String base64CredEncoder(String user, String pass){
        String concat = user + ":" + pass;
        return Base64.getEncoder().encodeToString(concat.getBytes());
    }
}

