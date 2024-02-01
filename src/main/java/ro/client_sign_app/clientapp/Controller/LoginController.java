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
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.application.Platform;
import javafx.stage.Stage;
import org.controlsfx.tools.Utils;
import javafx.scene.web.WebView;
import javafx.scene.web.WebEngine;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import ro.client_sign_app.clientapp.CSCLibrary.CSC_controller;
import ro.client_sign_app.clientapp.CSCLibrary.Oauth2_token_req;

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


    @FXML
    private void loginCSCAction(ActionEvent event) {

        Stage webViewStage = new Stage();
        WebView webView = new WebView();
        webViewStage.setScene(new Scene(webView, 900, 600));
        //webView.getEngine().load("https://google.com");
        webView.getEngine().load("https://rssdemo.certsign.ro/WSN.AuthorizationService_01/oauth2/authorize?client_id=81ac496c-3ab8-4e9d-bbe3-cf8ccc37f65c&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2F&culture=en&scope=service");

        WebEngine webEngine = webView.getEngine();
        webEngine.locationProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue.contains("http://localhost:8080"))
            {
                try {
                    URI uri = new URI(newValue);
                    String query = uri.getQuery();
                    String[] params = query.split("&");

                    for (String param : params) {
                        String[] keyValue = param.split("=");
                        if (keyValue.length == 2 && keyValue[0].equals("code")) {
                            String codeValue = keyValue[1];

                            Oauth2_token_req jsonBody = new Oauth2_token_req(codeValue);
                            String authToken = CSC_controller.oauth2_token(jsonBody);
                            if(authToken != null) {

                                try {
                                    FXMLLoader loader = new FXMLLoader(getClass().getResource("/ro/client_sign_app/clientapp/main2-view.fxml"));
                                    stage1 = new Stage();
                                    stage1.setTitle("Client pentru semnaturi electronice la distanta");
                                    stage1.setScene(new Scene(loader.load()));
                                    stage1.show();

                                    Main2Controller mainController = loader.getController();
                                    mainController.initAuthToken(authToken);

                                    webViewStage.close();
                                    final Node source = (Node) event.getSource();
                                    final Stage stage2 = (Stage) source.getScene().getWindow();
                                    stage2.close();

                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                            }

                            break;
                        }
                    }
                } catch (URISyntaxException e) {
                    e.printStackTrace();
                }

            }
        });

        webViewStage.setTitle("Autentificare Oauth2.0");
        webViewStage.show();

    }


}


