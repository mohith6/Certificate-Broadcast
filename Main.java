import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;

public class Main {

    private static String signingKey = "C:\\Users\\walke\\IdeaProjects\\CW2\\src\\main\\java\\pu_pakey.pfx"; // Keystore file path

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java Main <password> <file-to-sign>");
            return;
        }

        try {
            // Step 1: Load the keystore
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new FileInputStream(signingKey), args[0].toCharArray());

            // Step 2: Get the certificate from the keystore
            String alias = "1";
            Certificate cert = keyStore.getCertificate(alias);
            if (cert == null) {
                System.out.println("Certificate not found for alias: " + alias);
                return;
            }

            // Step 3: Convert the certificate to Base64-encoded string
            String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());
            System.out.println("Certificate Base64 encoded: " + certBase64);

            // Step 4: Configure SSLContext for both HTTP and HTTPS
            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, args[0].toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            // Step 5: Start both HTTP and HTTPS servers
            startHttpServer();
            startHttpsServer(sslContext);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Start a simple HTTP server (non-secure)
    private static void startHttpServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/broadcastCertificate", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String response = "Certificate (Base64 encoded) on HTTP:\n" + "Not Secure!";
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(200, response.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        });
        server.start();
        System.out.println("HTTP Server started at http://localhost:8000");
    }

    // Start an HTTPS server (secure)
    private static void startHttpsServer(SSLContext sslContext) throws IOException {
        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(8443), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));

        httpsServer.createContext("/broadcastCertificate", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                try {
                    // Authenticate client using their certificate
                    X509Certificate clientCert = (X509Certificate) exchange.getSSLSession().getPeerCertificates()[0];
                    if (clientCert != null) {
                        System.out.println("Client Certificate: " + clientCert.getSubjectDN());
                    } else {
                        System.out.println("No client certificate found!");
                    }

                    // Encrypt the message using the client's public key
                    PublicKey clientPublicKey = clientCert.getPublicKey();
                    String message = "This is a secret message from the server!";
                    byte[] encryptedMessage = encryptWithPublicKey(message, clientPublicKey);

                    // Send back the encrypted message (Base64 encoded)
                    String response = "Encrypted Message (Base64 encoded) on HTTPS:\n" + Base64.getEncoder().encodeToString(encryptedMessage);
                    exchange.getResponseHeaders().set("Content-Type", "text/plain");
                    exchange.sendResponseHeaders(200, response.getBytes().length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        httpsServer.start();
        System.out.println("HTTPS Server started at https://localhost:8443");
    }

    // Encrypt data using the client's public key
    private static byte[] encryptWithPublicKey(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    // Decrypt data using the client's private key (client-side)
    public static String decryptWithPrivateKey(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
