package ro.client_sign_app.clientapp.Signatures;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import ro.client_sign_app.clientapp.CSCLibrary.Cred_info_resp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


public class CAdESsignature {

    private CommonCertificateVerifier commonCertificateVerifier;
    private CAdESService service;
    private CAdESSignatureParameters parameters;
    private DSSDocument documentToBeSigned;

    public CAdESsignature(){
        parameters = new CAdESSignatureParameters();
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new CAdESService(commonCertificateVerifier);
    }

    public ToBeSigned doSignatureCSC(String docPath, SignatureLevel signatureLevel, DigestAlgorithm digestAlgorithm, Cred_info_resp keyInfo){
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
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
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

            // Stabilirea serviciului pentru marcare temporala a semnaturii detasate
            if (signatureLevel == SignatureLevel.CAdES_BASELINE_T){
                final String tspServer = "http://timestamp.digicert.com";
                OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
                tspSource.setDataLoader(new TimestampDataLoader());
                service.setTspSource(tspSource);
            }

            // Extragerea atributelor pentru semnare
            return service.getDataToSign(documentToBeSigned, parameters);

        } catch (CertificateException e){
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

        // Integrare semnatura in document
        DSSDocument signedDoc = service.signDocument(documentToBeSigned, parameters, signatureValue);
        return signedDoc;
    }

}
