package ro.client_sign_app.clientapp.Controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MainController {

    private String getCertUrl = "http://localhost:8080/api/getCert";

    private String authToken;
    void initAuthToken(String token){
        this.authToken = token;
    }

    @FXML
    private void getCertAction(ActionEvent event) {
        try {
            URL obj = new URL(getCertUrl);
            HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

            connection.setRequestMethod("GET");
            connection.setRequestProperty("Authorization", "Basic " + authToken);

            int responseCode = connection.getResponseCode();
            if(responseCode != 200){
                UtilsClass.infoBox("Eroare a serverului","Eroare",null);
                return;
            }

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            try {
                Files.write(Paths.get("D:\\Facultate\\Master\\Dizertatie\\Part2\\Certificate_Client\\cert.crt"), response.toString().getBytes());
            } catch (IOException e) {
                UtilsClass.infoBox("Eroare de salvare a fisierului","Erorr",null);
                e.printStackTrace();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @FXML
    private void uploadFileAction(ActionEvent event) {

    }

    @FXML
    private void getSignatureAction(ActionEvent event) {

    }


}
