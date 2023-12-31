package ro.client_sign_app.clientapp.Controller;
import ro.client_sign_app.clientapp.Signatures.ASiC_SwithCAdES;
import ro.client_sign_app.clientapp.Signatures.ASiC_SwithXAdES;

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
import ro.client_sign_app.clientapp.Signatures.Post_SignatureValue;
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

        // select params

        // init asic-s with xades

        String certPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\keystore\\user1.crt";
        String docPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1.xml";
        String outPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1SIGNED_test2.zip";
        String outPath2 = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1SIGNED_test3.zip";

        SignatureLevel signatureLevel = SignatureLevel.XAdES_BASELINE_B;
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

        ASiC_SwithXAdES signatureCreator = new ASiC_SwithXAdES();
        ToBeSigned toBeSigned = signatureCreator.doASiC_SwithXAdESsignature(certPath,docPath,signatureLevel,digestAlgorithm);

        // post
        String credentialID = "CX000001";
        String signAlgo = "sha256withRSA";
        String digestAlgo = "sha256";
        SignatureValue signatureValue = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned.getBytes(),credentialID,signAlgo,digestAlgo);

        // integrate
        boolean verifySignature = signatureCreator.integrateSignature(signatureValue, outPath);

        // CADES TEST
        SignatureLevel signatureLevel1 = SignatureLevel.CAdES_BASELINE_B;
        DigestAlgorithm digestAlgorithm1 = DigestAlgorithm.SHA256;

        ASiC_SwithCAdES signatureCreator1 = new ASiC_SwithCAdES();
        ToBeSigned toBeSigned1 = signatureCreator1.doASiC_SwithCAdESsignature(certPath,docPath,signatureLevel1,digestAlgorithm1);

        SignatureValue signatureValue1 = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned1.getBytes(),credentialID,signAlgo,digestAlgo);
        boolean verifySignature1 = signatureCreator1.integrateSignature(signatureValue1, outPath2);

    }
}
