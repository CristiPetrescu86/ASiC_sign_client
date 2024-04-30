package ro.client_sign_app.clientapp.Signatures;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxNativeFont;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import ro.client_sign_app.clientapp.CSCLibrary.Cred_info_resp;
import ro.client_sign_app.clientapp.Controller.PDFcoordsClass;

import java.awt.*;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;

public class PAdESsignature {

    private CommonCertificateVerifier commonCertificateVerifier;
    private PAdESService service;
    private PAdESSignatureParameters parameters;
    private DSSDocument documentToBeSigned;

    public PAdESsignature(){
        parameters = new PAdESSignatureParameters();
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new PAdESService(commonCertificateVerifier);
    }

    public ToBeSigned doSignatureCSC(String docPath, SignatureLevel signatureLevel, DigestAlgorithm digestAlgorithm, Cred_info_resp keyInfo, PDFcoordsClass panelCoords) {
        try {
            // Incarcarea certificatului digital al semnatarului
            byte[] decodedBytes = Base64.getDecoder().decode(keyInfo.getCert().getCertificates().get(0).replace("\n", ""));
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decodedBytes);
            X509Certificate signingCertificate = (X509Certificate) certificateFactory.generateCertificate(byteArrayInputStream);
            CertificateToken signingCert = new CertificateToken(signingCertificate);

            // Incarcare document ce urmeaza sa fie semnat
            documentToBeSigned = new FileDocument(new File(docPath));

            // Configurarea parametrilor pentru semnatura
            parameters.setSignatureLevel(signatureLevel);
            parameters.setDigestAlgorithm(digestAlgorithm);
            parameters.setSigningCertificate(signingCert);

            // Incarcarea lantului de certificate digitale
            List<CertificateToken> certificateChainList = new ArrayList<>();
            for(int i = 1; i < keyInfo.getCert().getCertificates().size(); i++) {
                byte[] decodedCert = Base64.getDecoder().decode(keyInfo.getCert().getCertificates().get(i).replace("\n", ""));
                CertificateFactory certificateChainFactory = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream decodedCertArrayInputStream = new ByteArrayInputStream(decodedCert);
                X509Certificate someCert = (X509Certificate) certificateChainFactory.generateCertificate(decodedCertArrayInputStream);
                CertificateToken someCertAux = new CertificateToken(someCert);
                certificateChainList.add(someCertAux);
            }
            parameters.setCertificateChain(certificateChainList);

            // Configurare imagine pentru chenarul semnaturii
            SignatureImageParameters imageParameters= new SignatureImageParameters();
            imageParameters.setImage(new InMemoryDocument(PAdESsignature.class.getResourceAsStream("/ro/client_sign_app/clientapp/pen-sign.png")));
            imageParameters.setBackgroundColor(Color.WHITE);
            imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.LEFT);
            imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

            // Configurare dimensiune chenar
            SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
            fieldParameters.setOriginX((float)panelCoords.getX());
            fieldParameters.setOriginY((float)panelCoords.getY()-20);
            fieldParameters.setWidth((float)panelCoords.getWidth());
            fieldParameters.setHeight((float)panelCoords.getHeight());
            imageParameters.setFieldParameters(fieldParameters);


            // Configurare parametrii text pentru semnatura
            Integer start = keyInfo.getCert().getSubjectDN().indexOf("CN=");
            String signerName = keyInfo.getCert().getSubjectDN().substring(start+3);
            String date = new Date().toString();
            String[] arrDate = date.split(" ");
            SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
            textParameters.setText("Semnat in original de\n" + signerName + " la:\n" + arrDate[0] + " " + arrDate[1] + " " + arrDate[2] + " " + arrDate[3] + "\n" + arrDate[4] + " " + arrDate[5]);
            textParameters.setTextColor(Color.BLUE);
            textParameters.setPadding(2);
            DSSFont font = new DSSJavaFont(Font.SANS_SERIF);
            font.setSize(10);
            textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
            textParameters.setFont(font);
            imageParameters.setTextParameters(textParameters);

            parameters.setImageParameters(imageParameters);
            parameters.bLevel().setSigningDate(new Date());

            // Activare semnatura vizibila
            service.setPdfObjFactory(new PdfBoxNativeObjectFactory());


            /* // Stabilirea serviciului pentru marcare temporala a semnaturii detasate
            if (signatureLevel == SignatureLevel.PAdES_BASELINE_T){
                final String tspServer = "http://timestamp.digicert.com";
                OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
                tspSource.setDataLoader(new TimestampDataLoader());
                service.setTspSource(tspSource);
            }*/

            // Extragerea atributelor pentru semnare
            return service.getDataToSign(documentToBeSigned, parameters);
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    public DSSDocument integrateSignatureCSC(String signedHash, SignatureAlgorithm SignAlgo)
    {
        // Setarea semnaturii obtinute
        SignatureValue signatureValue = new SignatureValue();
        byte[] decodedSignature = Base64.getDecoder().decode(signedHash);
        signatureValue.setAlgorithm(SignAlgo);
        signatureValue.setValue(decodedSignature);

        // Integrare semnatura in documents
        DSSDocument signedDoc = service.signDocument(documentToBeSigned, parameters, signatureValue);

        return signedDoc;
    }

    public DSSDocument augmentToTLevel(DSSDocument documentToBeAugmented){
        PAdESSignatureParameters tstParameters = new PAdESSignatureParameters();
        tstParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        CommonCertificateVerifier tstCertificateVerifier = new CommonCertificateVerifier();

        PAdESService tstService = new PAdESService(tstCertificateVerifier);
        final String tspServer = "http://timestamp.digicert.com";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new TimestampDataLoader());
        tstService.setTspSource(tspSource);

        DSSDocument tLevelDoc = tstService.extendDocument(documentToBeAugmented,tstParameters);

        return tLevelDoc;
    }

    public DSSDocument augmentToLTLevel(DSSDocument documentToBeAugmented, Cred_info_resp keyInfo){
        PAdESSignatureParameters ltvalidityParameters = new PAdESSignatureParameters();
        ltvalidityParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        CommonCertificateVerifier ltvalidityCertificateVerifier = new CommonCertificateVerifier();

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        try {
            for (int i = 0; i < keyInfo.getCert().getCertificates().size(); i++) {
                byte[] decodedCert = Base64.getDecoder().decode(keyInfo.getCert().getCertificates().get(i).replace("\n", ""));
                CertificateFactory certificateChainFactory = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream decodedCertArrayInputStream = new ByteArrayInputStream(decodedCert);
                X509Certificate someCert = (X509Certificate) certificateChainFactory.generateCertificate(decodedCertArrayInputStream);
                CertificateToken someCertAux = new CertificateToken(someCert);
                trustedCertificateSource.addCertificate(someCertAux);
            }
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        }

        ltvalidityCertificateVerifier.setTrustedCertSources(trustedCertificateSource);
        ltvalidityCertificateVerifier.setCrlSource(new OnlineCRLSource());
        ltvalidityCertificateVerifier.setOcspSource(new OnlineOCSPSource());
        ltvalidityCertificateVerifier.setAIASource(new DefaultAIASource());
        ltvalidityCertificateVerifier.addTrustedCertSources();

        PAdESService ltvalidityService = new PAdESService(ltvalidityCertificateVerifier);
        final String tspServer = "http://pki.codegic.com/codegic-service/timestamp";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setNonceSource(new SecureRandomNonceSource());
        tspSource.setPolicyOid("1.2.1");
        ltvalidityService.setTspSource(tspSource);

        DSSDocument tLevelDoc = ltvalidityService.extendDocument(documentToBeAugmented,ltvalidityParameters);

        return tLevelDoc;
    }



}
