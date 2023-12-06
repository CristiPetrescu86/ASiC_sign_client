package ro.client_sign_app.clientapp.Controller;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
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
import java.security.cert.X509Certificate;
import java.util.List;

// -----------
 import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
 import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
 import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
 import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
 import eu.europa.esig.dss.enumerations.DigestAlgorithm;
 import eu.europa.esig.dss.validation.CommonCertificateVerifier;
 import eu.europa.esig.dss.asic.common.*;
// -----------



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
        // D:\Facultate\Master\Dizertatie\Part2\TEST_SEMNATURI\xmlFile1.xml

        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken("D:\\Facultate\\Master\\Dizertatie\\Part2\\keystore\\user1_keystore.p12", new KeyStore.PasswordProtection("123456".toCharArray()))) {

            DSSDocument documentToBeSigned = new FileDocument(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1.xml"));

            ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry signingKey = keys.get(0);

            parameters.setSigningCertificate(signingKey.getCertificate());
            parameters.setCertificateChain(signingKey.getCertificateChain());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            ASiCWithXAdESService service = new ASiCWithXAdESService(commonCertificateVerifier);
            ToBeSigned dataToSign = service.getDataToSign(documentToBeSigned, parameters);

            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = token.sign(dataToSign,digestAlgorithm,signingKey);

            DSSDocument signedDoc = service.signDocument(documentToBeSigned,parameters,signatureValue);

            try (OutputStream out = new FileOutputStream( "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1SIGNED.zip"))
            {
                signedDoc.writeTo(out);
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
}
