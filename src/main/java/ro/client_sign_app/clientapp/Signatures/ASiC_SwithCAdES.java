package ro.client_sign_app.clientapp.Signatures;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import ro.client_sign_app.clientapp.CSCLibrary.Cred_info_resp;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ASiC_SwithCAdES {

    private CommonCertificateVerifier commonCertificateVerifier;
    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters parameters;
    private DSSDocument documentToBeSigned;
    private String signatureLevel;

    public ASiC_SwithCAdES(){
        parameters = new ASiCWithCAdESSignatureParameters();
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new ASiCWithCAdESService(commonCertificateVerifier);
    }

    public ToBeSigned doSignature(String certPath, String docPath, SignatureLevel signatureLevel, DigestAlgorithm digestAlgorithm) {
        try {
            FileInputStream fileInputStream = new FileInputStream(certPath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate signingCertificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            CertificateToken signingCert = new CertificateToken(signingCertificate);

            documentToBeSigned = new FileDocument(new File(docPath));

            parameters.setSignatureLevel(signatureLevel);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
            parameters.setDigestAlgorithm(digestAlgorithm);

            parameters.setSigningCertificate(signingCert);
            //parameters.setCertificateChain(signingCert);

            // Timestamp
            if (signatureLevel == SignatureLevel.CAdES_BASELINE_T){
                final String tspServer = "http://timestamp.digicert.com";
                OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
                tspSource.setDataLoader(new TimestampDataLoader());
                service.setTspSource(tspSource);
            }

            return service.getDataToSign(documentToBeSigned, parameters);
        }
        catch (IOException | CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    public DSSDocument integrateSignature(SignatureValue signatureValue)
    {
        DSSDocument signedDoc = service.signDocument(documentToBeSigned, parameters, signatureValue);
        return signedDoc;
    }

    public ToBeSigned doSignatureCSC(String docPath, SignatureLevel signatureLevel, DigestAlgorithm digestAlgorithm, Cred_info_resp keyInfo) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(keyInfo.getCert().getCertificates().get(0).replace("\n", ""));
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decodedBytes);
            X509Certificate signingCertificate = (X509Certificate) certificateFactory.generateCertificate(byteArrayInputStream);
            CertificateToken signingCert = new CertificateToken(signingCertificate);

            documentToBeSigned = new FileDocument(new File(docPath));

            parameters.setSignatureLevel(signatureLevel);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
            parameters.setDigestAlgorithm(digestAlgorithm);

            parameters.setSigningCertificate(signingCert);

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

            // Timestamp
            if (signatureLevel == SignatureLevel.CAdES_BASELINE_T){
                final String tspServer = "http://timestamp.digicert.com";
                OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
                tspSource.setDataLoader(new TimestampDataLoader());
                service.setTspSource(tspSource);
            }

            return service.getDataToSign(documentToBeSigned, parameters);
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    public DSSDocument integrateSignatureCSC(String signedHash, SignatureAlgorithm SignAlgo)
    {
        SignatureValue signatureValue = new SignatureValue();
        byte[] decodedSignature = Base64.getDecoder().decode(signedHash);
        signatureValue.setAlgorithm(SignAlgo);
        signatureValue.setValue(decodedSignature);

        DSSDocument signedDoc = service.signDocument(documentToBeSigned, parameters, signatureValue);
        return signedDoc;
    }

}
