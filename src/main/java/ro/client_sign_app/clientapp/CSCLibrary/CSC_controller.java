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
import java.util.List;

public class CSC_controller {

    private static String url = "https://rssdemo.certsign.ro/WSN.AuthorizationService_01/oauth2/token";
    private static String get_cred_url = "https://rssdemo.certsign.ro/CSC.ApiService_01/csc/v1/credentials/list";
    private static String get_info_url = "https://rssdemo.certsign.ro/CSC.ApiService_01/csc/v1/credentials/info";

    public static String oauth2_token(Oauth2_token_req body) {

        try {
            URL obj = new URL(url);
            HttpsURLConnection connection = (HttpsURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            byte[] postData = body.returnBody().getBytes(StandardCharsets.UTF_8);

            try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
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

    public static List<String> credentials_list(String authToken){
        try {
            URL obj = new URL(get_cred_url);
            HttpsURLConnection connection = (HttpsURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "Bearer " + authToken);

            Cred_list_req credListObj = new Cred_list_req(10);
            ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
            String json = ow.writeValueAsString(credListObj);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = json.getBytes("utf-8");
                os.write(input, 0, input.length);
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
                Cred_list_resp myDataFromJson = objectMapper.readValue(response.toString(), Cred_list_resp.class);

                return myDataFromJson.getCredentials();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    public static Cred_info_resp credentials_info(String authToken, Cred_info_req credInfoObj){
        try {
            URL obj = new URL(get_info_url);
            HttpsURLConnection connection = (HttpsURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "Bearer " + authToken);

            ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
            String json = ow.writeValueAsString(credInfoObj);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = json.getBytes("utf-8");
                os.write(input, 0, input.length);
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
                Cred_info_resp credentialInfo = objectMapper.readValue(response.toString(), Cred_info_resp.class);

                return credentialInfo;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
