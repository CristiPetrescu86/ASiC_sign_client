package ro.client_sign_app.clientapp.Controller;

import javafx.scene.control.Alert;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
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

    public static String getFileExtension(String filePath) {
        Path path = Paths.get(filePath);
        String fileName = path.getFileName().toString();
        int lastDotIndex = fileName.lastIndexOf('.');
        if (lastDotIndex != -1 && lastDotIndex < fileName.length() - 1) {
            return fileName.substring(lastDotIndex + 1);
        } else {
            return null;
        }
    }

    public static String computeAuthorizeLink(String credentialID, String hash){
        return "https://rssdemo.certsign.ro/WSN.AuthorizationService_01/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2F&culture=en&scope=credential&numSignatures=1&client_id=81ac496c-3ab8-4e9d-bbe3-cf8ccc37f65c&credentialID="
                + credentialID + "&hash=" + hash;
    }

    public static String computeAuthorizeLink(String credentialID, ArrayList<String> hash){
        String authLink = "https://rssdemo.certsign.ro/WSN.AuthorizationService_01/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2F&culture=en&scope=credential&numSignatures=" + hash.size() + "&client_id=81ac496c-3ab8-4e9d-bbe3-cf8ccc37f65c&credentialID="
                + credentialID + "&hash=";
        for(int i = 0; i < hash.size(); i++){
            authLink += hash.get(i);
            authLink += ",";
        }
        return authLink.substring(0,authLink.length() - 1);
    }
}

