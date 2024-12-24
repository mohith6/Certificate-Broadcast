import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Objects;

public class Main {

    private static String signingKey = "C:\\Users\\walke\\IdeaProjects\\CW2\\src\\main\\java\\pu_pakey.pfx";

    public static void main(String[] args) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, SignatureException, InvalidKeyException, NoSuchProviderException {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(signingKey), args[0].toCharArray());

        Enumeration<String> e = keyStore.aliases();
        while (e.hasMoreElements()) {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate( e.nextElement());
            if (!Objects.isNull(certificate))
                System.out.println(certificate);
        }
        Certificate cert = keyStore.getCertificate("1");
        PublicKey pk = cert.getPublicKey();

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("1",
                new KeyStore.PasswordProtection(args[0].toCharArray()));
        PrivateKey privateKey = pkEntry.getPrivateKey();
        cert.verify(pk);

        Signature rsaSign = Signature.getInstance("SHA256withRSA");
        rsaSign.initSign(privateKey);
        FileInputStream inputStream = new FileInputStream(args[1]);

        rsaSign.update(inputStream.readAllBytes());
        byte[] signature = rsaSign.sign();
        System.out.println(new String(signature, StandardCharsets.UTF_8));
        System.out.println("signing successful");
    }
}