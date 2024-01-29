package org.example;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

// https://docs.oracle.com/en/java/javase/11/security/java-security-overview1.html
public class JdkTest {

    @Test
    public void createKeyPairAndEncryptAndDecrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(3072);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        //KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        //byte[] serializedPublicKey = publicKey.getEncoded();
        //EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(serializedPublicKey);
        //PublicKey deserializedPublicKey = keyFactory.generatePublic(encodedKeySpec);

        String secret = "Veldig hemmelig";
        byte[] serializedSecret = secret.getBytes(StandardCharsets.UTF_8);

        Cipher encryptionCipher = Cipher.getInstance("RSA");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSerializedSecret = encryptionCipher.doFinal(serializedSecret);

        Cipher decryptionCipher = Cipher.getInstance("RSA");
        decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSerializedSecret = decryptionCipher.doFinal(encryptedSerializedSecret);

        assertArrayEquals(serializedSecret, decryptedSerializedSecret);

        String deserializedSecret = new String(decryptedSerializedSecret, StandardCharsets.UTF_8);
        assertEquals(secret, deserializedSecret);
    }

    @Test
    public void bitLevelTcpWithTls() throws IOException {
        // Don't do HTTP like this! :-)
        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket("samarbeid.digdir.no", 443);
        InputStream in = sslSocket.getInputStream();
        OutputStream out = sslSocket.getOutputStream();

        String outString =
                "GET / HTTP/1.1\n" +
                "Host: samarbeid.digdir.no\n" +
                "Content-Type: text/html; charset=UTF-8\n\n";
        byte[] outBytes = outString.getBytes(StandardCharsets.UTF_8);
        out.write(outBytes);

        // Don't do streaming like this! :-)
        sslSocket.setSoTimeout(1000);
        try {
            while (true) {
                char c = (char) in.read();
                System.out.print(c);
            }
        } catch (SocketTimeoutException e) {
            // Lets the client timeout instead of handling the HTTP Content-Length response header
        }

        out.close();
        in.close();
    }
}
