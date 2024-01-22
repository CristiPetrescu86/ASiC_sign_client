package ro.client_sign_app.clientapp.Signatures;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class ASiC_EwithTST {

    private CommonCertificateVerifier commonCertificateVerifier;
    private ASiCWithCAdESService service;
    private ASiCWithCAdESTimestampParameters timestampingParameters;
    private List<DSSDocument> documentsToBeSigned;

    public ASiC_EwithTST(){
        timestampingParameters = new ASiCWithCAdESTimestampParameters ();
        commonCertificateVerifier = new CommonCertificateVerifier();
        service = new ASiCWithCAdESService(commonCertificateVerifier);
        documentsToBeSigned = new ArrayList<>();
    }

    public boolean doTimeAssertion(List<String> docPath, String outFilePath) {
        try {
            for (String doc : docPath)
                documentsToBeSigned.add(new FileDocument(doc));

            final String tspServer = "http://timestamp.digicert.com";
            OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
            tspSource.setDataLoader(new TimestampDataLoader());

            service.setTspSource(tspSource);
            timestampingParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

            DSSDocument timestampedDoc = service.timestamp(documentsToBeSigned, timestampingParameters);

            try (OutputStream out = new FileOutputStream(outFilePath)) {
                timestampedDoc.writeTo(out);
            }

            return true;
        }
        catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}
