package ro.client_sign_app.clientapp.Signatures;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import ro.client_sign_app.clientapp.Controller.PostParams;
import ro.client_sign_app.clientapp.Controller.UtilsClass;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class Post_SignatureValue {
    public static SignatureValue requestSignatureValue(String signHashUrl, String authToken, byte[] toBeSigned, String credID, String signAlgo, String digestAlgo) {
        try {
            URL obj = new URL(signHashUrl);
            HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Basic " + authToken);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            // CREATE AND SEND JSON MESSAGE
            PostParams postParams = new PostParams();
            postParams.setCredID(credID);
            postParams.setSignAlgo(signAlgo);
            postParams.setDigestAlgo(digestAlgo);
            postParams.setHashToBeSigned(Base64.getEncoder().encodeToString(toBeSigned));

            ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
            String json = ow.writeValueAsString(postParams);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = json.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                return null;
            }

            SignatureValue signatureValue = new SignatureValue();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                byte[] decodedSignature = Base64.getDecoder().decode(response.toString());
                signatureValue.setAlgorithm(SignatureAlgorithm.RSA_SHA256);
                signatureValue.setValue(decodedSignature);


                return signatureValue;
            }

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }
}
