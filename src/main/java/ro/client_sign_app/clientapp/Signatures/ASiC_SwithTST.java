package ro.client_sign_app.clientapp.Signatures;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;



import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ASiC_SwithTST {

    private CommonCertificateVerifier commonCertificateVerifier;
    private ASiCWithCAdESService service;
    private ASiCWithCAdESTimestampParameters timestampingParameters;
    private DSSDocument documentToBeSigned;

    public ASiC_SwithTST(){
        timestampingParameters = new ASiCWithCAdESTimestampParameters ();
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new ASiCWithCAdESService(commonCertificateVerifier);
    }

    public DSSDocument doTimeAssertion(String docPath) {
        // Incarcare fisier si stabilire server marca temporala
        documentToBeSigned = new FileDocument(new File(docPath));
        final String tspServer = "http://timestamp.digicert.com";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new TimestampDataLoader());

        service.setTspSource(tspSource);
        timestampingParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        // Marcare temporala a documentului
        DSSDocument timestampedDoc = service.timestamp(documentToBeSigned, timestampingParameters);
        return timestampedDoc;
    }

}
