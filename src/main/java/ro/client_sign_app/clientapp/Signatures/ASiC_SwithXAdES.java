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

public class ASiC_SwithXAdES {

    private CommonCertificateVerifier commonCertificateVerifier;
    private ASiCWithXAdESService service;
    private ASiCWithXAdESSignatureParameters parameters;
    private DSSDocument documentToBeSigned;
    private String signatureLevel;

    public ASiC_SwithXAdES()
    {
        parameters = new ASiCWithXAdESSignatureParameters();
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new ASiCWithXAdESService(commonCertificateVerifier);
    }

    public ToBeSigned doASiC_SwithXAdESsignature(String certPath,String docPath, SignatureLevel signatureLevel,DigestAlgorithm digestAlgorithm)
    {
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

            return service.getDataToSign(documentToBeSigned, parameters);
        }
        catch (IOException | CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean integrateSignature(SignatureValue signatureValue, String outFilePath)
    {
        DSSDocument signedDoc = service.signDocument(documentToBeSigned, parameters, signatureValue);

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
