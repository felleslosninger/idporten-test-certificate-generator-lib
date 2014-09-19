package no.difi;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

/**
 * Hello world!
 *
 */
public class App 
{
    char[] password = "changeit".toCharArray();
    private KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password);

    public App() throws Exception{

        KeyStore pkcs12 = KeyStore.getInstance("pkcs12");
        pkcs12.load(null, password);

        VirksomhetGenerator generator = new VirksomhetGenerator();
        KeyStore.PrivateKeyEntry root = generator.generateRot();
        pkcs12.setEntry("root", root, protection);
        pkcs12.setEntry("intermediate", generator.generateIntermediate(), protection);
        generator.generateVirksomhet("987654321");

        FileOutputStream file = new FileOutputStream("test.p12");
        pkcs12.store(file, password);
    }

    public static void main( String[] args ) throws Exception
    {
        new App();

    }
}
