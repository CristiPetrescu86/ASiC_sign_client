package ro.client_sign_app.clientapp.Signatures;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class ASiC_EwithXAdES {

    private CommonCertificateVerifier commonCertificateVerifier;
    private ASiCWithXAdESService service;
    private ASiCWithXAdESSignatureParameters parameters;
    private List<DSSDocument> documentsToBeSigned;
    private String signatureLevel;

    public ASiC_EwithXAdES()
    {
        parameters = new ASiCWithXAdESSignatureParameters();
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new ASiCWithXAdESService(commonCertificateVerifier);
        documentsToBeSigned = new ArrayList<>();
    }

    public ToBeSigned doSignature(String certPath, List<String> docPath, SignatureLevel signatureLevel, DigestAlgorithm digestAlgorithm)
    {
        try {
            FileInputStream fileInputStream = new FileInputStream(certPath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate signingCertificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            CertificateToken signingCert = new CertificateToken(signingCertificate);

            for (String doc : docPath)
                documentsToBeSigned.add(new FileDocument(doc));

            parameters.setSignatureLevel(signatureLevel);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
            parameters.setDigestAlgorithm(digestAlgorithm);

            parameters.setSigningCertificate(signingCert);
            //parameters.setCertificateChain(signingCert);

            return service.getDataToSign(documentsToBeSigned, parameters);
        }
        catch (IOException | CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean integrateSignature(SignatureValue signatureValue, String outFilePath)
    {
        DSSDocument signedDoc = service.signDocument(documentsToBeSigned, parameters, signatureValue);

        try (OutputStream out = new FileOutputStream(outFilePath)) {
            signedDoc.writeTo(out);
        }
        catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }


}
