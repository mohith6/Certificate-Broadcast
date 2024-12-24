# Certificate-Broadcast
Broadcasting certificates to the clients over HTTP and HTTPS protocols and validating client's certificate over HTTPS using mutual SSL authentication

Generate the keystore and SSL certificate for the server:
keytool -genkeypair -v -keystore server-keystore.jks -keyalg RSA -keysize 2048 -validity 365 -storepass changeit -keypass changeit -dname "CN=localhost"

Enabling mutual authentication:
keytool -genkeypair -v -keystore client-keystore.jks -keyalg RSA -keysize 2048 -validity 365 -storepass changeit -keypass changeit -dname "CN=client"

With the Client certificate, test the encrypted response:
curl --cert client-keystore.jks:changeit https://localhost:8443/broadcastCertificate

