package ro.client_sign_app.clientapp.Controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.application.Platform;
import javafx.stage.Stage;
import org.controlsfx.tools.Utils;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class LoginController {

    @FXML
    private TextField usernameField;

    @FXML
    private PasswordField passwordField;

    private String loginURL = "https://localhost:8080/api/login";
    private static String successLogin = "Authentication successful";

    private Stage stage1;
    private Scene scene1;
    private Parent root1;

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
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };

            URL obj = new URL(loginURL);
            HttpsURLConnection connection = (HttpsURLConnection) obj.openConnection();

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            connection.setSSLSocketFactory(sc.getSocketFactory());

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
                //root1 = FXMLLoader.load(getClass().getResource("/ro/client_sign_app/clientapp/main-view.fxml"));
                FXMLLoader loader = new FXMLLoader(getClass().getResource("/ro/client_sign_app/clientapp/main-view.fxml"));
                stage1 = new Stage();
                stage1.setTitle("Main Application Window");
                stage1.setScene(new Scene(loader.load()));
                stage1.show();

                MainController mainController = loader.getController();
                mainController.initAuthToken(base64CredEncoded);

                final Node source = (Node) event.getSource();
                final Stage stage2 = (Stage) source.getScene().getWindow();
                stage2.close();
            }
        } catch (IOException | NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }

    }



}


