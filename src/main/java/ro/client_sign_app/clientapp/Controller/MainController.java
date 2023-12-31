package ro.client_sign_app.clientapp.Controller;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

// -----------
 import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
 import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
 import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
 import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
 import eu.europa.esig.dss.asic.common.*;
import org.controlsfx.tools.Utils;
// -----------



public class MainController {

    private String getCertUrl = "http://localhost:8080/api/getCert";
    private String signHashUrl = "http://localhost:8080/api/signHash";

    private String authToken;

    void initAuthToken(String token) {
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
            if (responseCode != 200) {
                UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
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
                UtilsClass.infoBox("Eroare de salvare a fisierului", "Error", null);
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

        try {
            String certPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\keystore\\user1.crt";
            FileInputStream fileInputStream = new FileInputStream(certPath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate signingCertificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            CertificateToken signingCert = new CertificateToken(signingCertificate);

            DSSDocument documentToBeSigned = new FileDocument(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1.xml"));

            ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            parameters.setSigningCertificate(signingCert);
            //parameters.setCertificateChain(signingCert);

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            ASiCWithXAdESService service = new ASiCWithXAdESService(commonCertificateVerifier);
            ToBeSigned dataToSign = service.getDataToSign(documentToBeSigned, parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();


            URL obj = new URL(signHashUrl);
            HttpURLConnection connection = (HttpURLConnection) obj.openConnection();

            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Basic " + authToken);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            // CREATE AND SEND JSON MESSAGE
            PostParams postParams = new PostParams();
            postParams.setCredID("CX000001");
            postParams.setSignAlgo("sha256withRSA");
            postParams.setDigestAlgo("sha256");
            postParams.setHashToBeSigned(Base64.getEncoder().encodeToString(dataToSign.getBytes()));

            ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
            String json = ow.writeValueAsString(postParams);

            try(OutputStream os = connection.getOutputStream()) {
                byte[] input = json.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                return;
            }

            SignatureValue signatureValue = new SignatureValue();
            try(BufferedReader br = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                byte[] decodedSignature = Base64.getDecoder().decode(response.toString());
                signatureValue.setAlgorithm(SignatureAlgorithm.RSA_SHA256);
                signatureValue.setValue(decodedSignature);
                //signatureValue = new SignatureValue();
                //signatureValue.setValue(decodedSignature);
                //signatureValue.setValue(decodedSignature);
                //System.out.println(response.toString());
            }

            DSSDocument signedDoc = service.signDocument(documentToBeSigned, parameters, signatureValue);

            try (OutputStream out = new FileOutputStream("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1SIGNED_test2.zip")) {
                signedDoc.writeTo(out);
            }

        }
        catch (IOException | CertificateException e) {
            e.printStackTrace();
        }

    }
}
