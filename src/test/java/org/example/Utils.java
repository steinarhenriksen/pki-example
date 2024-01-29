package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Utils {

    public static X509Certificate getX509Certificate(Path certificateFile) throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream inputStream = Files.newInputStream(certificateFile);
        X509Certificate encryptionCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        return encryptionCertificate;
    }

    public static void unzipAndPrint(Path zipFile) throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(Files.newInputStream(zipFile));
        ZipEntry zipEntry = null;
        while ((zipEntry = zipInputStream.getNextEntry()) != null) {
            System.out.println("File:");
            System.out.println(zipEntry.getName());
            System.out.println();
            System.out.println("Contents:");
            if (!zipEntry.isDirectory()) {
                byte[] bytes = zipInputStream.readAllBytes();
                System.out.println(new String(bytes));
            }
            System.out.println("---");
        }
    }

}
