package ro.client_sign_app.clientapp.Controller;
import eu.europa.esig.dss.spi.DSSUtils;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.FileChooser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import ro.client_sign_app.clientapp.CSCLibrary.*;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.stage.Stage;
import ro.client_sign_app.clientapp.Signatures.*;

import javax.swing.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.List;

public class Main2Controller {

    private String authToken;
    private ArrayList<String> filePaths;
    private List<String> credentials;
    private PDFcoordsClass panelCoords;
    private final HashMap<String,String> algoHashMap = new HashMap<String,String>(
            Map.ofEntries(
                    new AbstractMap.SimpleEntry<String, String>("1.2.840.113549.1.1.1", "RSA"),
                    new AbstractMap.SimpleEntry<String, String>("1.2.840.113549.1.1.11", "RSAwithSHA256"),
                    new AbstractMap.SimpleEntry<String, String>("1.2.840.113549.1.1.13", "RSAwithSHA512")
            )
    );
    private final HashMap<String,String> reverseAlgoHashMap = new HashMap<String,String>(
            Map.ofEntries(
                    new AbstractMap.SimpleEntry<String, String>("RSA", "1.2.840.113549.1.1.1"),
                    new AbstractMap.SimpleEntry<String, String>("RSAwithSHA256", "1.2.840.113549.1.1.11"),
                    new AbstractMap.SimpleEntry<String, String>("RSAwithSHA512", "1.2.840.113549.1.1.13")
            )
    );

    private final HashMap<String,SignatureAlgorithm> signingAlgorithm = new HashMap<String,SignatureAlgorithm>(
            Map.ofEntries(
                    new AbstractMap.SimpleEntry<String, SignatureAlgorithm>("RSAwithSHA256",SignatureAlgorithm.RSA_SHA256),
                    new AbstractMap.SimpleEntry<String, SignatureAlgorithm>("RSAwithSHA512",SignatureAlgorithm.RSA_SHA512)
            )
    );

    private Cred_info_resp keyInfo;

    void initMainPageToken(String token) {
        this.authToken = token;
        filePaths = new ArrayList<>();
        credentials = new ArrayList<>();
        credentials = CSC_controller.credentials_list(authToken);
        ObservableList<String> data = FXCollections.observableArrayList();
        for (String cred : credentials){
            data.add(cred);
        }
        credID.setItems(data);
    }

    @FXML
    private ComboBox<String> credID;

    @FXML
    private void credInfoForKey(ActionEvent event) {
        String selectedValue = credID.getValue();
        Cred_info_req credInfoObj = new Cred_info_req(selectedValue,"chain",true,true,"ro");
        keyInfo = CSC_controller.credentials_info(authToken,credInfoObj);
        if(keyInfo == null){
            UtilsClass.infoBox("Eroare server", "Eroare", null);
            return;
        }

        ObservableList<String> data = FXCollections.observableArrayList();
        for(String algoSupported : keyInfo.getKey().getAlgo()){
            String foundSupportedAlgo = algoHashMap.get(algoSupported);
            if(foundSupportedAlgo != null)
                data.add(foundSupportedAlgo);
        }
        signAlgo.setItems(data);
    }

    @FXML
    private void uploadFileAction(ActionEvent event) {
        Stage stage = new Stage();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Alege documentele pentru semnat");

        //fileChooser.setInitialDirectory(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI"));

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
        stage.close();
    }

    @FXML
    private ComboBox<String> signAlgo;
    @FXML
    private ComboBox<String> containerType;
    @FXML
    private ComboBox<String> signLevel;

    private void saveFile(DSSDocument signedDoc, String fileChosen) {
        if(signedDoc == null)
        {
            UtilsClass.infoBox("Semnatura invalida", "Eroare", null);
            return;
        }

        try {
            OutputStream out = new FileOutputStream(fileChosen);
            signedDoc.writeTo(out);
            out.close();

        } catch (IOException e) {
            UtilsClass.infoBox("Eroare de salvare a fisierului", "Error", null);
            e.printStackTrace();
        }
    }

    private String chooseSaveFilePath(){
        Stage stage = new Stage();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Salveaza fisier");
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("Zip archive (*.zip)", "*.zip");
        //fileChooser.setInitialDirectory(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI"));
        fileChooser.getExtensionFilters().add(extFilter);
        File fileChosen = fileChooser.showSaveDialog(stage);
        stage.close();
        return fileChosen.getAbsolutePath();
    }

    private String chooseSaveFilePathPDF(){
        Stage stage = new Stage();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Salveaza fisier");
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("PDF document (*.pdf)", "*.pdf");
        //fileChooser.setInitialDirectory(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI"));
        fileChooser.getExtensionFilters().add(extFilter);
        File fileChosen = fileChooser.showSaveDialog(stage);
        stage.close();
        return fileChosen.getAbsolutePath();
    }

    private String chooseSaveFilePathXML(){
        Stage stage = new Stage();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Salveaza fisier");
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("XML document (*.xml)", "*.xml");
        //fileChooser.setInitialDirectory(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI"));
        fileChooser.getExtensionFilters().add(extFilter);
        File fileChosen = fileChooser.showSaveDialog(stage);
        stage.close();
        return fileChosen.getAbsolutePath();
    }

    private String chooseSaveFilePathp7s(){
        Stage stage = new Stage();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Salveaza fisier");
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("p7s document (*.p7s)", "*.p7s");
        //fileChooser.setInitialDirectory(new File("D:\\Facultate\\Master\\Dizertatie\\Part2\\TEST_SEMNATURI"));
        fileChooser.getExtensionFilters().add(extFilter);
        File fileChosen = fileChooser.showSaveDialog(stage);
        stage.close();
        return fileChosen.getAbsolutePath();
    }

    @FXML
    private void checkPDFselected(ActionEvent event)
    {
        if(containerType.getValue().equals("PAdES")) {
            signLevel.setValue("PAdES B-B");
            if(filePaths.isEmpty()){
                UtilsClass.infoBox("Incarcati documentul PDF inainte", "Error", null);
            }
            else {
                String extension = String.valueOf(Optional.ofNullable(filePaths.get(0))
                        .filter(f -> f.contains("."))
                        .map(f -> f.substring(filePaths.get(0).lastIndexOf(".") + 1)));
                if(!extension.equals("Optional[pdf]")) {
                    UtilsClass.infoBox("Documentul incarcat trebuie sa fie PDF", "Error", null);
                }

                File file = new File(filePaths.get(0));
                try {
                    SignaturePanelExtractor extractor = new SignaturePanelExtractor(file, rect -> {
                        panelCoords = new PDFcoordsClass(rect.getMinX(),rect.getMinY(),rect.getWidth(),rect.getHeight());

                    });
                    JFrame frame = new JFrame();
                    frame.add(extractor);
                    frame.pack();
                    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                    frame.setVisible(true);

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @FXML
    private void getSignatureAction(ActionEvent event) {
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

        if(containerTypeValue.equals("XAdES"))
        {
            for (String filePath: filePaths){
                if(!UtilsClass.getFileExtension(filePath).equals("xml"))
                {
                    UtilsClass.infoBox("Selectati doar fisier .xml!", "Eroare", null);
                    return;
                }
            }
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
        else if(signLevelValue.equals("CAdES B-T"))
            signatureLevel = SignatureLevel.CAdES_BASELINE_T;
        else
            signatureLevel = SignatureLevel.PAdES_BASELINE_B;

        DigestAlgorithm digestAlgorithm = null;
        String signAlgo = null;
        if(signAlgoValue.equals("RSAwithSHA256")) {
            digestAlgorithm = DigestAlgorithm.SHA256;
            signAlgo = reverseAlgoHashMap.get(signAlgoValue);
        }
        else if(signAlgoValue.equals("RSAwithSHA512")) {
            digestAlgorithm = DigestAlgorithm.SHA512;
            signAlgo = reverseAlgoHashMap.get(signAlgoValue);
        }
        else {
            UtilsClass.infoBox("Algo not supported", "Error", null);
            return;
        }

        if(containerTypeValue.equals("ASiC-S") && (signLevelValue.equals("XAdES B-B") || signLevelValue.equals("XAdES B-T"))) {
            ASiC_SwithXAdES signatureCreator = new ASiC_SwithXAdES();
            ToBeSigned toBeSigned = signatureCreator.doSignatureCSC(filePaths.get(0), signatureLevel, digestAlgorithm, keyInfo);

            byte[] toBeSignedDigest = DSSUtils.digest(digestAlgorithm, toBeSigned.getBytes());
            List<String> hashesList = new ArrayList<>();
            hashesList.add(Base64.getEncoder().encodeToString(toBeSignedDigest));

            String authorizeLink = UtilsClass.computeAuthorizeLink(credIDValue,Base64.getUrlEncoder().encodeToString(toBeSignedDigest));

            String fileSavePath = chooseSaveFilePath();

            Stage webViewStage = new Stage();
            WebView webView = new WebView();
            webViewStage.setScene(new Scene(webView, 900, 600));
            webView.getEngine().load(authorizeLink);

            WebEngine webEngine = webView.getEngine();
            String finalSignAlgo = signAlgo;
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
                                String SAD = CSC_controller.oauth2_token(jsonBody);
                                Sign_signHash_req signHashBody = new Sign_signHash_req(credIDValue,hashesList,finalSignAlgo,SAD);

                                if(SAD != null) {
                                    String signedDigest = CSC_controller.signatures_signHash(authToken,signHashBody);
                                    if(signedDigest == null){
                                        UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                                        return;
                                    }
                                    DSSDocument signedDocument = signatureCreator.integrateSignatureCSC(signedDigest,signingAlgorithm.get(signAlgoValue));
                                    saveFile(signedDocument,fileSavePath);
                                    filePaths.clear();
                                    webViewStage.close();
                                }
                                break;
                            }
                        }

                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }

                }
            });

            webViewStage.setTitle("Autorizare cheie privata");
            webViewStage.show();
        }
        else if(containerTypeValue.equals("ASiC-E") && (signLevelValue.equals("XAdES B-B") || signLevelValue.equals("XAdES B-T"))){
            ASiC_EwithXAdES signatureCreator = new ASiC_EwithXAdES();
            ToBeSigned toBeSigned = signatureCreator.doSignatureCSC(filePaths,signatureLevel,digestAlgorithm,keyInfo);

            byte[] toBeSignedDigest = DSSUtils.digest(digestAlgorithm, toBeSigned.getBytes());

            List<String> hashesList = new ArrayList<>();
            hashesList.add(Base64.getEncoder().encodeToString(toBeSignedDigest));

            String authorizeLink = UtilsClass.computeAuthorizeLink(credIDValue,Base64.getUrlEncoder().encodeToString(toBeSignedDigest));
            String fileSavePath = chooseSaveFilePath();

            Stage webViewStage = new Stage();
            WebView webView = new WebView();
            webViewStage.setScene(new Scene(webView, 900, 600));
            webView.getEngine().load(authorizeLink);

            WebEngine webEngine = webView.getEngine();
            String finalSignAlgo = signAlgo;
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
                                String SAD = CSC_controller.oauth2_token(jsonBody);
                                Sign_signHash_req signHashBody = new Sign_signHash_req(credIDValue,hashesList,finalSignAlgo,SAD);

                                if(SAD != null) {
                                    String signedDigest = CSC_controller.signatures_signHash(authToken,signHashBody);
                                    if(signedDigest == null){
                                        UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                                        return;
                                    }
                                    DSSDocument signedDocument = signatureCreator.integrateSignatureCSC(signedDigest,signingAlgorithm.get(signAlgoValue));
                                    saveFile(signedDocument,fileSavePath);
                                    filePaths.clear();
                                    webViewStage.close();
                                }
                                break;
                            }
                        }

                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }

                }
            });

            webViewStage.setTitle("Autorizare cheie privata");
            webViewStage.show();
        }
        else if(containerTypeValue.equals("ASiC-S") && (signLevelValue.equals("CAdES B-B") || signLevelValue.equals("CAdES B-T"))){
            ASiC_SwithCAdES signatureCreator = new ASiC_SwithCAdES();
            ToBeSigned toBeSigned = signatureCreator.doSignatureCSC(filePaths.get(0), signatureLevel, digestAlgorithm, keyInfo);

            byte[] toBeSignedDigest = DSSUtils.digest(digestAlgorithm, toBeSigned.getBytes());
            List<String> hashesList = new ArrayList<>();
            hashesList.add(Base64.getEncoder().encodeToString(toBeSignedDigest));

            String authorizeLink = UtilsClass.computeAuthorizeLink(credIDValue,Base64.getUrlEncoder().encodeToString(toBeSignedDigest));

            String fileSavePath = chooseSaveFilePath();

            Stage webViewStage = new Stage();
            WebView webView = new WebView();
            webViewStage.setScene(new Scene(webView, 900, 600));
            webView.getEngine().load(authorizeLink);

            WebEngine webEngine = webView.getEngine();
            String finalSignAlgo = signAlgo;
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
                                String SAD = CSC_controller.oauth2_token(jsonBody);
                                Sign_signHash_req signHashBody = new Sign_signHash_req(credIDValue,hashesList,finalSignAlgo,SAD);

                                if(SAD != null) {
                                    String signedDigest = CSC_controller.signatures_signHash(authToken,signHashBody);
                                    if(signedDigest == null){
                                        UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                                        return;
                                    }
                                    DSSDocument signedDocument = signatureCreator.integrateSignatureCSC(signedDigest,signingAlgorithm.get(signAlgoValue));
                                    saveFile(signedDocument,fileSavePath);
                                    filePaths.clear();
                                    webViewStage.close();
                                }
                                break;
                            }
                        }

                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }

                }
            });

            webViewStage.setTitle("Autorizare cheie privata");
            webViewStage.show();
        }
        else if(containerTypeValue.equals("ASiC-E") && (signLevelValue.equals("CAdES B-B") || signLevelValue.equals("CAdES B-T"))){
            ASiC_EwithCAdES signatureCreator = new ASiC_EwithCAdES();
            ToBeSigned toBeSigned = signatureCreator.doSignatureCSC(filePaths,signatureLevel,digestAlgorithm,keyInfo);

            byte[] toBeSignedDigest = DSSUtils.digest(digestAlgorithm, toBeSigned.getBytes());

            List<String> hashesList = new ArrayList<>();
            hashesList.add(Base64.getEncoder().encodeToString(toBeSignedDigest));

            String authorizeLink = UtilsClass.computeAuthorizeLink(credIDValue,Base64.getUrlEncoder().encodeToString(toBeSignedDigest));
            String fileSavePath = chooseSaveFilePath();

            Stage webViewStage = new Stage();
            WebView webView = new WebView();
            webViewStage.setScene(new Scene(webView, 900, 600));
            webView.getEngine().load(authorizeLink);

            WebEngine webEngine = webView.getEngine();
            String finalSignAlgo = signAlgo;
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
                                String SAD = CSC_controller.oauth2_token(jsonBody);
                                Sign_signHash_req signHashBody = new Sign_signHash_req(credIDValue,hashesList,finalSignAlgo,SAD);

                                if(SAD != null) {
                                    String signedDigest = CSC_controller.signatures_signHash(authToken,signHashBody);
                                    if(signedDigest == null){
                                        UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                                        return;
                                    }
                                    DSSDocument signedDocument = signatureCreator.integrateSignatureCSC(signedDigest,signingAlgorithm.get(signAlgoValue));
                                    saveFile(signedDocument,fileSavePath);
                                    filePaths.clear();
                                    webViewStage.close();
                                }
                                break;
                            }
                        }

                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }

                }
            });

            webViewStage.setTitle("Autorizare cheie privata");
            webViewStage.show();
        }
        else if(containerTypeValue.equals("PAdES")){
            PAdESsignature signatureCreator = new PAdESsignature();
            ToBeSigned toBeSigned = signatureCreator.doSignatureCSC(filePaths.get(0), signatureLevel, digestAlgorithm, keyInfo, panelCoords);

            byte[] toBeSignedDigest = DSSUtils.digest(digestAlgorithm, toBeSigned.getBytes());
            List<String> hashesList = new ArrayList<>();
            hashesList.add(Base64.getEncoder().encodeToString(toBeSignedDigest));

            String authorizeLink = UtilsClass.computeAuthorizeLink(credIDValue,Base64.getUrlEncoder().encodeToString(toBeSignedDigest));

            String fileSavePath = chooseSaveFilePathPDF();

            Stage webViewStage = new Stage();
            WebView webView = new WebView();
            webViewStage.setScene(new Scene(webView, 900, 600));
            webView.getEngine().load(authorizeLink);

            WebEngine webEngine = webView.getEngine();
            String finalSignAlgo = signAlgo;
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
                                String SAD = CSC_controller.oauth2_token(jsonBody);
                                Sign_signHash_req signHashBody = new Sign_signHash_req(credIDValue,hashesList,finalSignAlgo,SAD);

                                if(SAD != null) {
                                    String signedDigest = CSC_controller.signatures_signHash(authToken,signHashBody);
                                    if(signedDigest == null){
                                        UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                                        return;
                                    }
                                    DSSDocument signedDocument = signatureCreator.integrateSignatureCSC(signedDigest,signingAlgorithm.get(signAlgoValue));
                                    saveFile(signedDocument,fileSavePath);
                                    filePaths.clear();
                                    webViewStage.close();
                                }
                                break;
                            }
                        }

                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }

                }
            });

            webViewStage.setTitle("Autorizare cheie privata");
            webViewStage.show();
        }
        else if(containerTypeValue.equals("XAdES") && ((signLevelValue.equals("XAdES B-B") || signLevelValue.equals("XAdES B-T"))))
        {
            XAdESsignature signatureCreator = new XAdESsignature();
            ToBeSigned toBeSigned = signatureCreator.doSignatureCSC(filePaths.get(0), signatureLevel, digestAlgorithm, keyInfo);

            byte[] toBeSignedDigest = DSSUtils.digest(digestAlgorithm, toBeSigned.getBytes());
            List<String> hashesList = new ArrayList<>();
            hashesList.add(Base64.getEncoder().encodeToString(toBeSignedDigest));

            String authorizeLink = UtilsClass.computeAuthorizeLink(credIDValue,Base64.getUrlEncoder().encodeToString(toBeSignedDigest));

            String fileSavePath = chooseSaveFilePathXML();

            Stage webViewStage = new Stage();
            WebView webView = new WebView();
            webViewStage.setScene(new Scene(webView, 900, 600));
            webView.getEngine().load(authorizeLink);

            WebEngine webEngine = webView.getEngine();
            String finalSignAlgo = signAlgo;
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
                                String SAD = CSC_controller.oauth2_token(jsonBody);
                                Sign_signHash_req signHashBody = new Sign_signHash_req(credIDValue,hashesList,finalSignAlgo,SAD);

                                if(SAD != null) {
                                    String signedDigest = CSC_controller.signatures_signHash(authToken,signHashBody);
                                    if(signedDigest == null){
                                        UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                                        return;
                                    }
                                    DSSDocument signedDocument = signatureCreator.integrateSignatureCSC(signedDigest,signingAlgorithm.get(signAlgoValue));
                                    saveFile(signedDocument,fileSavePath);
                                    filePaths.clear();
                                    webViewStage.close();
                                }
                                break;
                            }
                        }

                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }

                }
            });

            webViewStage.setTitle("Autorizare cheie privata");
            webViewStage.show();
        }
        else if(containerTypeValue.equals("CAdES") && ((signLevelValue.equals("CAdES B-B") || signLevelValue.equals("CAdES B-T"))))
        {
            CAdESsignature signatureCreator = new CAdESsignature();
            ToBeSigned toBeSigned = signatureCreator.doSignatureCSC(filePaths.get(0), signatureLevel, digestAlgorithm, keyInfo);

            byte[] toBeSignedDigest = DSSUtils.digest(digestAlgorithm, toBeSigned.getBytes());
            List<String> hashesList = new ArrayList<>();
            hashesList.add(Base64.getEncoder().encodeToString(toBeSignedDigest));

            String authorizeLink = UtilsClass.computeAuthorizeLink(credIDValue,Base64.getUrlEncoder().encodeToString(toBeSignedDigest));

            String fileSavePath = chooseSaveFilePathp7s();

            Stage webViewStage = new Stage();
            WebView webView = new WebView();
            webViewStage.setScene(new Scene(webView, 900, 600));
            webView.getEngine().load(authorizeLink);

            WebEngine webEngine = webView.getEngine();
            String finalSignAlgo = signAlgo;
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
                                String SAD = CSC_controller.oauth2_token(jsonBody);
                                Sign_signHash_req signHashBody = new Sign_signHash_req(credIDValue,hashesList,finalSignAlgo,SAD);

                                if(SAD != null) {
                                    String signedDigest = CSC_controller.signatures_signHash(authToken,signHashBody);
                                    if(signedDigest == null){
                                        UtilsClass.infoBox("Eroare a serverului", "Eroare", null);
                                        return;
                                    }
                                    DSSDocument signedDocument = signatureCreator.integrateSignatureCSC(signedDigest,signingAlgorithm.get(signAlgoValue));
                                    saveFile(signedDocument,fileSavePath);
                                    filePaths.clear();
                                    webViewStage.close();
                                }
                                break;
                            }
                        }

                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }

                }
            });

            webViewStage.setTitle("Autorizare cheie privata");
            webViewStage.show();
        }
        else{
            if(filePaths.size()>1){
                ASiC_EwithTST timestamp1 = new ASiC_EwithTST();
                DSSDocument signedDocument = timestamp1.doTimeAssertion(filePaths);
                String fileChosen = chooseSaveFilePath();
                saveFile(signedDocument,fileChosen);
            }
            else{
                ASiC_SwithTST timestamp1 = new ASiC_SwithTST();
                DSSDocument signedDocument = timestamp1.doTimeAssertion(filePaths.get(0));
                String fileChosen = chooseSaveFilePath();
                saveFile(signedDocument,fileChosen);
            }
        }
    }

}
