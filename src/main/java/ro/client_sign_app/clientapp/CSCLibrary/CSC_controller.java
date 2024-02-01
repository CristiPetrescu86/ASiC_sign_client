package ro.client_sign_app.clientapp.CSCLibrary;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.module.SimpleModule;
import ro.client_sign_app.clientapp.Controller.PostParams;
import ro.client_sign_app.clientapp.Controller.UtilsClass;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CSC_controller {

    private static String url = "https://rssdemo.certsign.ro/WSN.AuthorizationService_01/oauth2/token";

    public static String oauth2_token(Oauth2_token_req body) {

        try {
            URL obj = new URL(url);
            HttpsURLConnection connection = (HttpsURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            byte[] postData = body.returnBody().getBytes(StandardCharsets.UTF_8);

            try(DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
                wr.write(postData);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                return null;
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                ObjectMapper objectMapper = new ObjectMapper();
                Oauth2_token_resp myDataFromJson = objectMapper.readValue(response.toString(), Oauth2_token_resp.class);
                return myDataFromJson.getAccess_token();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
