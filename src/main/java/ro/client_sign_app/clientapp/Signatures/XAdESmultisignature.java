package ro.client_sign_app.clientapp.Signatures;

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
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import ro.client_sign_app.clientapp.CSCLibrary.Cred_info_resp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class XAdESmultisignature {

    private CommonCertificateVerifier commonCertificateVerifier;
    private ArrayList<XAdESService> services;
    private ArrayList<XAdESSignatureParameters> parametersList;
    private ArrayList<DSSDocument> documentsToBeSigned;

    public XAdESmultisignature(Integer instances){
        parametersList = new ArrayList<>();
        services = new ArrayList<>();
        documentsToBeSigned = new ArrayList<>();

        for (int i = 0; i < instances; i++){
            parametersList.add(new XAdESSignatureParameters());
            commonCertificateVerifier = new CommonCertificateVerifier();
            services.add(new XAdESService(commonCertificateVerifier));
        }
    }

    public ArrayList<ToBeSigned> doSignature(ArrayList<String> docPath, SignatureLevel signatureLevel, DigestAlgorithm digestAlgorithm, Cred_info_resp keyInfo){
        try {
            // Incarcarea certificatului digital al semnatarului
            byte[] decodedBytes = Base64.getDecoder().decode(keyInfo.getCert().getCertificates().get(0).replace("\n", ""));
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decodedBytes);
            X509Certificate signingCertificate = (X509Certificate) certificateFactory.generateCertificate(byteArrayInputStream);
            CertificateToken signingCert = new CertificateToken(signingCertificate);

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

            ArrayList<ToBeSigned> toBeSignedDocuments = new ArrayList<>();

            // Incarcare document ce urmeaza sa fie semnat
            for (int i = 0; i < docPath.size(); i++){
                documentsToBeSigned.add(new FileDocument(new File(docPath.get(i))));

                // Configurarea parametrilor pentru semnatura
                parametersList.get(i).setSignatureLevel(signatureLevel);
                parametersList.get(i).setSignaturePackaging(SignaturePackaging.ENVELOPED);
                parametersList.get(i).setDigestAlgorithm(digestAlgorithm);
                parametersList.get(i).setSigningCertificate(signingCert);

                parametersList.get(i).setCertificateChain(certificateChainList);

                // Stabilirea serviciului pentru marcare temporala a semnaturii detasate
                if (signatureLevel == SignatureLevel.XAdES_BASELINE_T){
                    final String tspServer = "http://timestamp.digicert.com";
                    OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
                    tspSource.setDataLoader(new TimestampDataLoader());
                    services.get(i).setTspSource(tspSource);
                }

                toBeSignedDocuments.add(services.get(i).getDataToSign(documentsToBeSigned.get(i),parametersList.get(i)));
            }

            return toBeSignedDocuments;
        } catch (CertificateException e){
            e.printStackTrace();
            return null;
        }
    }

    public ArrayList<DSSDocument> integrateSignature(List<String> signedHash, SignatureAlgorithm SignAlgo){
        ArrayList<DSSDocument> signedDocs = new ArrayList<>();

        for (int i = 0; i < signedHash.size(); i++) {
            // Setarea semnaturii obtinute
            SignatureValue signatureValue = new SignatureValue();
            byte[] decodedSignature = Base64.getDecoder().decode(signedHash.get(i));
            signatureValue.setAlgorithm(SignAlgo);
            signatureValue.setValue(decodedSignature);

            // Integrare semnatura in document
            DSSDocument signedDoc = services.get(i).signDocument(documentsToBeSigned.get(i), parametersList.get(i), signatureValue);
            signedDocs.add(signedDoc);
        }

        return signedDocs;
    }

}
