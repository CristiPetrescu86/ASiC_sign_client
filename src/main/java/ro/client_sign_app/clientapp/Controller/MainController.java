package ro.client_sign_app.clientapp.Controller;
import javafx.scene.control.Alert;
import javafx.scene.control.ComboBox;
import javafx.stage.FileChooser;
import ro.client_sign_app.clientapp.Signatures.*;

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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
// -----------



public class MainController {

    private final String getCertUrl = "https://localhost:8080/api/getCert";
    private final String signHashUrl = "https://localhost:8080/api/signHash";

    private String authToken;
    private ArrayList<String> filePaths;

    void initAuthToken(String token) {
        this.authToken = token;
        filePaths = new ArrayList<>();
    }

    @FXML
    private Stage stage;

    @FXML
    private void getCertAction(ActionEvent event) {
        String signingCert = Get_SigningCert.requestSignatureValue(getCertUrl,authToken);

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Salveaza fisier");
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("Certificate file (*.crt)", "*.crt");
        fileChooser.setInitialDirectory(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\Certificate_Client"));
        fileChooser.getExtensionFilters().add(extFilter);
        File file = fileChooser.showSaveDialog(stage);

        if(signingCert == null)
        {
            UtilsClass.infoBox("Eroare server", "Eroare", null);
            return;
        }

        try {
            FileWriter writer = new FileWriter(file);
            writer.write(signingCert);
            writer.close();
        } catch (IOException e) {
            UtilsClass.infoBox("Eroare de salvare a fisierului", "Error", null);
            e.printStackTrace();
        }

    }

    @FXML
    private void uploadFileAction(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Alege documentele pentru semnat");

        fileChooser.setInitialDirectory(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI"));

        List<File> selectedFiles = fileChooser.showOpenMultipleDialog(stage);
        filePaths.clear();

        if (selectedFiles != null) {
            for (File file : selectedFiles) {
                filePaths.add(file.getAbsolutePath());
            }
        } else {
            UtilsClass.infoBox("Niciun fisier selectat","Warning",null);
            return;
        }
    }

    @FXML
    private ComboBox<String> credID;
    @FXML
    private ComboBox<String> signAlgo;
    @FXML
    private ComboBox<String> containerType;
    @FXML
    private ComboBox<String> signLevel;

    private void saveFile(DSSDocument signedDoc) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Salveaza fisier");
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("Zip archive (*.zip)", "*.zip");
        fileChooser.setInitialDirectory(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI"));
        fileChooser.getExtensionFilters().add(extFilter);
        File fileChosen = fileChooser.showSaveDialog(stage);

        if(signedDoc == null)
        {
            UtilsClass.infoBox("Semnatura invalida", "Eroare", null);
            return;
        }

        try {
            OutputStream out = new FileOutputStream(fileChosen.getAbsolutePath());
            signedDoc.writeTo(out);

        } catch (IOException e) {
            UtilsClass.infoBox("Eroare de salvare a fisierului", "Error", null);
            e.printStackTrace();
        }
    }

    @FXML
    private void getSignatureAction(ActionEvent event) {

        String certPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\keystore\\user1.crt";
        String credIDValue = credID.getValue();
        String signAlgoValue = signAlgo.getValue();
        String containerTypeValue = containerType.getValue();
        String signLevelValue = signLevel.getValue();

        if(filePaths.isEmpty())
        {
            UtilsClass.infoBox("Niciun fisier selectat", "Eroare", null);
            return;
        }

        if(filePaths.size() > 1 && containerTypeValue.equals("ASiC-S") && signLevelValue.contains("CAdES"))
        {
            UtilsClass.infoBox("Selectati ASiC-E!", "Eroare", null);
            return;
        }

        if(signLevelValue.contains("XAdES")) {
            for (String filePath: filePaths)
            {
                if(!UtilsClass.getFileExtension(filePath).equals("xml"))
                {
                    UtilsClass.infoBox("Selectati doar fisiere .xml!", "Eroare", null);
                    return;
                }
            }
        }

        SignatureLevel signatureLevel = null;
        if(signLevelValue.equals("XAdES B-B"))
            signatureLevel = SignatureLevel.XAdES_BASELINE_B;
        else if(signLevelValue.equals("XAdES B-T"))
            signatureLevel = SignatureLevel.XAdES_BASELINE_T;
        else if(signLevelValue.equals("CAdES B-B"))
            signatureLevel = SignatureLevel.CAdES_BASELINE_B;
        else
            signatureLevel = SignatureLevel.CAdES_BASELINE_T;

        DigestAlgorithm digestAlgorithm = null;
        String signAlgo = null;
        String digestAlgo = null;
        if(signAlgoValue.equals("RSAwithSHA256")) {
            digestAlgorithm = DigestAlgorithm.SHA256;
            signAlgo = "sha256withRSA";
            digestAlgo = "sha256";
        }

        if(containerTypeValue.equals("ASiC-S") && signLevelValue.equals("XAdES B-B")) {
            ASiC_SwithXAdES signatureCreator = new ASiC_SwithXAdES();
            ToBeSigned toBeSigned = signatureCreator.doSignature(certPath,filePaths.get(0),signatureLevel,digestAlgorithm);
            SignatureValue signatureValue = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned.getBytes(),credIDValue,signAlgo,digestAlgo);
            DSSDocument signedDocument = signatureCreator.integrateSignature(signatureValue);
            saveFile(signedDocument);
        }
        else if(containerTypeValue.equals("ASiC-E") && signLevelValue.equals("XAdES B-B")){

        }
        else if(containerTypeValue.equals("ASiC-S") && signLevelValue.equals("CAdES B-B")){

        }
        else if(containerTypeValue.equals("ASiC-E") && signLevelValue.equals("CAdES B-B")){

        }
        else{

        }

        /*
        // init asic-s with xades

        String certPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\keystore\\user1.crt";
        String docPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1.xml";
        String outPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1SIGNED_test2.zip";
        String outPath2 = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1SIGNED_test3.zip";
        String outPath3 = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1SIGNED_test4.zip";


        SignatureLevel signatureLevel = SignatureLevel.XAdES_BASELINE_B;
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

        ASiC_SwithXAdES signatureCreator = new ASiC_SwithXAdES();
        ToBeSigned toBeSigned = signatureCreator.doASiC_SwithXAdESsignature(certPath,docPath,signatureLevel,digestAlgorithm);

        // post
        String credentialID = "CX000001";

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

        // ASIC Timestamp TEST

        ASiC_SwithTST timestamp1 = new ASiC_SwithTST();
        timestamp1.doASiC_SwithTimestamp(docPath,outPath3);

        // ASIC-E with XAdES

        List<String> docPath_3 = List.of(new String[]{"D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1.xml","D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile2.xml","D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile3.xml"});
        String outPath4 = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\asiceXADES_test1.zip";

        ASiC_EwithXAdES signatureCreator2 = new ASiC_EwithXAdES();
        ToBeSigned toBeSigned2 = signatureCreator2.doSignature(certPath,docPath_3,signatureLevel,digestAlgorithm);
        SignatureValue signatureValue2 = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned2.getBytes(),credentialID,signAlgo,digestAlgo);
        boolean verifySignature2 = signatureCreator2.integrateSignature(signatureValue2,outPath4);

        // ASIC-E with CAdES

        List<String> docPath_4 = List.of(new String[]{"D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\xmlFile1.xml","D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\Bitcoin.pdf","D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\pict1.jpg"});
        String outPath5 = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\asiceCADES_test1.zip";
        ASiC_EwithCAdES signatureCreator3 = new ASiC_EwithCAdES();
        ToBeSigned toBeSigned3 = signatureCreator3.doSignature(certPath,docPath_4,signatureLevel1,digestAlgorithm1);
        SignatureValue signatureValue3 = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned3.getBytes(),credentialID,signAlgo,digestAlgo);
        boolean verifySignature3 = signatureCreator3.integrateSignature(signatureValue3,outPath5);


        // ASIC-E with timestamp

        String outPath6 = "D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI\\asiceTST_test1.zip";
        ASiC_EwithTST timestamp2 = new ASiC_EwithTST();
        timestamp2.doTimeAssertion(docPath_4,outPath6);
        */


    }
}
