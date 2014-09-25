package no.difi;

import java.io.FileOutputStream;
import java.security.KeyStore;

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

        TestVirksomhetGenerator generator = new TestVirksomhetGenerator();
        KeyStore.PrivateKeyEntry root = generator.generateRot();
        KeyStore.PrivateKeyEntry intermediate = generator.generateIntermediate(root);
        KeyStore.PrivateKeyEntry virksomhet = generator.generateVirksomhet("987654321", intermediate);

        pkcs12.setEntry("root", root, protection);
        pkcs12.setEntry("intermediate", intermediate, protection);
        pkcs12.setEntry("virksomhet", virksomhet, protection);

        FileOutputStream file = new FileOutputStream("test.p12");
        pkcs12.store(file, password);
    }

    public static void main( String[] args ) throws Exception
    {
        new App();

    }
}
