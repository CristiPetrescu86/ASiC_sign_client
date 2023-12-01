package ro.client_sign_app.clientapp.Controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.application.Platform;
import org.controlsfx.tools.Utils;

public class LoginController {

    @FXML
    private TextField usernameField;

    @FXML
    private PasswordField passwordField;

    private String loginURL = "http://localhost:8080/api/login";
    private static String successLogin = "Authentication successful";

    @FXML
    private void loginButtonAction(ActionEvent event) {
        String username = usernameField.getText();
        String password = passwordField.getText();

        if ("".equals(username)) {
            UtilsClass.infoBox("Numele utilizator nu a fost introdus","Error",null);
            return;
        }
        if ("".equals(password)) {
            UtilsClass.infoBox("Parola nu a fost introdusa","Error",null);
            return;
        }

        String base64CredEncoded = UtilsClass.base64CredEncoder(username, password);

        try {
            URL obj = new URL(loginURL);
            HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", "Basic " + base64CredEncoded);

            int responseCode = connection.getResponseCode();
            if(responseCode != 200){
                UtilsClass.infoBox("Credentiale incorecte","Eroare",null);
                return;
            }

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            if(successLogin.equals(response.toString())) {
                // REDIRECT OK PAGE
                UtilsClass.infoBox(response.toString(), "rest", null);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }



}


