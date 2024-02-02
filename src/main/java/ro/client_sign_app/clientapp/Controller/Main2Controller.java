package ro.client_sign_app.clientapp.Controller;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ListView;
import javafx.stage.FileChooser;
import ro.client_sign_app.clientapp.CSCLibrary.CSC_controller;
import ro.client_sign_app.clientapp.CSCLibrary.Cred_info_req;
import ro.client_sign_app.clientapp.CSCLibrary.Cred_info_resp;
import ro.client_sign_app.clientapp.Signatures.*;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.stage.Stage;
import java.io.*;
import java.util.*;
import java.util.stream.Stream;

public class Main2Controller {

    private String authToken;
    private ArrayList<String> filePaths;
    private List<String> credentials;
    private HashMap<String,String> algoHashMap = new HashMap<String,String>(
            Map.ofEntries(
                    new AbstractMap.SimpleEntry<String, String>("1.2.840.113549.1.1.1", "RSA"),
                    new AbstractMap.SimpleEntry<String, String>("1.2.840.113549.1.1.11", "RSAwithSHA256"),
                    new AbstractMap.SimpleEntry<String, String>("1.2.840.113549.1.1.13", "RSAwithSHA512")
            )
    );


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
    private Stage stage;

    @FXML
    private void credInfoForKey(ActionEvent event) {
        String selectedValue = credID.getValue();
        Cred_info_req credInfoObj = new Cred_info_req(selectedValue,"chain",true,true,"ro");
        Cred_info_resp keyInfo = CSC_controller.credentials_info(authToken,credInfoObj);
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

//        String certPath = "D:\\Facultate\\Master\\Dizertatie\\Part2\\keystore\\user1.crt";
//        String credIDValue = credID.getValue();
//        String signAlgoValue = signAlgo.getValue();
//        String containerTypeValue = containerType.getValue();
//        String signLevelValue = signLevel.getValue();
//
//        if(filePaths.isEmpty())
//        {
//            UtilsClass.infoBox("Niciun fisier selectat", "Eroare", null);
//            return;
//        }
//
//        if(filePaths.size() > 1 && containerTypeValue.equals("ASiC-S") && signLevelValue.contains("CAdES"))
//        {
//            UtilsClass.infoBox("Selectati ASiC-E!", "Eroare", null);
//            return;
//        }
//
//        if(signLevelValue.contains("XAdES")) {
//            for (String filePath: filePaths)
//            {
//                if(!UtilsClass.getFileExtension(filePath).equals("xml"))
//                {
//                    UtilsClass.infoBox("Selectati doar fisiere .xml!", "Eroare", null);
//                    return;
//                }
//            }
//        }
//
//        SignatureLevel signatureLevel = null;
//        if(signLevelValue.equals("XAdES B-B"))
//            signatureLevel = SignatureLevel.XAdES_BASELINE_B;
//        else if(signLevelValue.equals("XAdES B-T"))
//            signatureLevel = SignatureLevel.XAdES_BASELINE_T;
//        else if(signLevelValue.equals("CAdES B-B"))
//            signatureLevel = SignatureLevel.CAdES_BASELINE_B;
//        else
//            signatureLevel = SignatureLevel.CAdES_BASELINE_T;
//
//        DigestAlgorithm digestAlgorithm = null;
//        String signAlgo = null;
//        String digestAlgo = null;
//        if(signAlgoValue.equals("RSAwithSHA256")) {
//            digestAlgorithm = DigestAlgorithm.SHA256;
//            signAlgo = "sha256withRSA";
//            digestAlgo = "sha256";
//        }
//
//        if(containerTypeValue.equals("ASiC-S") && (signLevelValue.equals("XAdES B-B") || signLevelValue.equals("XAdES B-T"))) {
//            ASiC_SwithXAdES signatureCreator = new ASiC_SwithXAdES();
//            ToBeSigned toBeSigned = signatureCreator.doSignature(certPath,filePaths.get(0),signatureLevel,digestAlgorithm);
//            SignatureValue signatureValue = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned.getBytes(),credIDValue,signAlgo,digestAlgo);
//            DSSDocument signedDocument = signatureCreator.integrateSignature(signatureValue);
//            saveFile(signedDocument);
//        }
//        else if(containerTypeValue.equals("ASiC-E") && (signLevelValue.equals("XAdES B-B") || signLevelValue.equals("XAdES B-T"))){
//            ASiC_EwithXAdES signatureCreator = new ASiC_EwithXAdES();
//            ToBeSigned toBeSigned = signatureCreator.doSignature(certPath,filePaths,signatureLevel,digestAlgorithm);
//            SignatureValue signatureValue = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned.getBytes(),credIDValue,signAlgo,digestAlgo);
//            DSSDocument signedDocument = signatureCreator.integrateSignature(signatureValue);
//            saveFile(signedDocument);
//        }
//        else if(containerTypeValue.equals("ASiC-S") && (signLevelValue.equals("CAdES B-B") || signLevelValue.equals("CAdES B-T"))){
//            ASiC_SwithCAdES signatureCreator = new ASiC_SwithCAdES();
//            ToBeSigned toBeSigned = signatureCreator.doSignature(certPath,filePaths.get(0),signatureLevel,digestAlgorithm);
//            SignatureValue signatureValue = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned.getBytes(),credIDValue,signAlgo,digestAlgo);
//            DSSDocument signedDocument = signatureCreator.integrateSignature(signatureValue);
//            saveFile(signedDocument);
//        }
//        else if(containerTypeValue.equals("ASiC-E") && (signLevelValue.equals("CAdES B-B") || signLevelValue.equals("CAdES B-T"))){
//            ASiC_EwithCAdES signatureCreator = new ASiC_EwithCAdES();
//            ToBeSigned toBeSigned = signatureCreator.doSignature(certPath,filePaths,signatureLevel,digestAlgorithm);
//            SignatureValue signatureValue = Post_SignatureValue.requestSignatureValue(signHashUrl,authToken,toBeSigned.getBytes(),credIDValue,signAlgo,digestAlgo);
//            DSSDocument signedDocument = signatureCreator.integrateSignature(signatureValue);
//            saveFile(signedDocument);
//        }
//        else{
//            if(filePaths.size()>1){
//                ASiC_EwithTST timestamp1 = new ASiC_EwithTST();
//                DSSDocument signedDocument = timestamp1.doTimeAssertion(filePaths);
//                saveFile(signedDocument);
//            }
//            else{
//                ASiC_SwithTST timestamp1 = new ASiC_SwithTST();
//                DSSDocument signedDocument = timestamp1.doTimeAssertion(filePaths.get(0));
//                saveFile(signedDocument);
//            }
//        }
    }
}
