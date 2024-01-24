package ro.client_sign_app.clientapp.Signatures;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class ASiC_EwithCAdES {

    private CommonCertificateVerifier commonCertificateVerifier;
    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters parameters;
    private List<DSSDocument> documentsToBeSigned;
    private String signatureLevel;

    public ASiC_EwithCAdES(){
        parameters = new ASiCWithCAdESSignatureParameters();
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new ASiCWithCAdESService(commonCertificateVerifier);
        documentsToBeSigned = new ArrayList<>();
    }

    public ToBeSigned doSignature(String certPath, List<String> docPath, SignatureLevel signatureLevel, DigestAlgorithm digestAlgorithm) {
        try {
            FileInputStream fileInputStream = new FileInputStream(certPath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate signingCertificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            CertificateToken signingCert = new CertificateToken(signingCertificate);

            for (String doc : docPath)
                documentsToBeSigned.add(new FileDocument(doc));

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

            return service.getDataToSign(documentsToBeSigned, parameters);
        }
        catch (IOException | CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    public DSSDocument integrateSignature(SignatureValue signatureValue)
    {
        DSSDocument signedDoc = service.signDocument(documentsToBeSigned, parameters, signatureValue);
        return signedDoc;
    }
}
