package org.example;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

// https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Digital+Signature+Service+-++DSS
// https://github.com/esig/dss
public class DssAsicTest {

    @Test
    public void createAssociatedSignatureContainerUsingXmlAdvancedSignature() throws IOException {
        Path fileToSign = Files.createTempFile("temp-", ".txt");
        Files.writeString(fileToSign, "This is the file to sign.");

        Path asicFile = Path.of("asice-xades-using-dss.zip");
        if (Files.exists(asicFile)) {
            Files.delete(asicFile);
        }

        DSSDocument dssDocument = new FileDocument(fileToSign.toFile());

        try (SignatureTokenConnection tokenConnection = new Pkcs12SignatureToken("keystore.p12", new KeyStore.PasswordProtection("password".toCharArray()))) {
            DSSPrivateKeyEntry privateKey = tokenConnection.getKeys().get(0);

            ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();

            ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier);

            ToBeSigned toBeSigned = service.getDataToSign(dssDocument, parameters);

            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = tokenConnection.sign(toBeSigned, digestAlgorithm, privateKey);

            DSSDocument signedDssDocument = service.signDocument(dssDocument, parameters, signatureValue);
            signedDssDocument.writeTo(Files.newOutputStream(asicFile));

            Utils.unzipAndPrint(asicFile);
        }
    }

}
