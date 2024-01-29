package org.example;

import no.difi.asic.*;
import no.difi.asic.extras.CmsEncryptedAsicWriter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

// https://github.com/felleslosninger/efm-asic
public class DifiAsicTest {

    @Test
    public void createAssociatedSignatureContainerUsingXmlAdvancedSignature() throws IOException {
        Path fileToSign = Files.createTempFile("file-to-sign-", ".txt");
        Files.writeString(fileToSign, "This is the file to sign.");

        Path asicFile = Path.of("asice-xades-using-difi.zip");
        if (Files.exists(asicFile)) {
            Files.delete(asicFile);
        }

        AsicWriterFactory factory = AsicWriterFactory.newFactory();
        AsicWriter writer = factory.newContainer(asicFile);

        writer.add(fileToSign);
        writer.sign(new File("keystore.p12"), "password", "password");

        Utils.unzipAndPrint(asicFile);
    }

    @Test
    public void createEncryptedAssociatedSignatureContainerUsingXmlAdvancedSignature() throws IOException, CertificateException {
        X509Certificate encryptionCertificate = Utils.getX509Certificate(Path.of("kunde-cert.pem"));

        Path fileToSign = Files.createTempFile("file-to-sign-", ".txt");
        Files.writeString(fileToSign, "This is the file to sign.");

        Path asicFile = Path.of("encrypted-asice-xades-using-difi.zip");
        if (Files.exists(asicFile)) {
            Files.delete(asicFile);
        }

        AsicWriterFactory factory = AsicWriterFactory.newFactory();
        AsicWriter writer = factory.newContainer(asicFile);

        CmsEncryptedAsicWriter encryptedWriter = new CmsEncryptedAsicWriter(writer, encryptionCertificate, CMSAlgorithm.AES256_GCM);

        encryptedWriter.addEncrypted(fileToSign);
        encryptedWriter.sign(new File("keystore.p12"), "password", "password");

        Utils.unzipAndPrint(asicFile);
    }

}
