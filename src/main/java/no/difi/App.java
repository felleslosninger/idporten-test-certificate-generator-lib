package no.difi;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;
import sun.security.x509.X509CRLImpl;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Hello world!
 *
 */
public class App 
{
    char[] password = "changeit".toCharArray();
    private KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password);


    public App(KeyStore.PrivateKeyEntry rootEntry, KeyStore.PrivateKeyEntry intermediateEntry) throws Exception {
        KeyStore pkcs12 = KeyStore.getInstance("JKS");
        pkcs12.load(null, password);

        TestVirksomhetGenerator generator = new TestVirksomhetGenerator();
        KeyStore.PrivateKeyEntry root = rootEntry == null ? generator.generateRot() : rootEntry;
        X509Certificate rootCertificate = (X509Certificate) root.getCertificate();

        KeyStore.PrivateKeyEntry intermediate = intermediateEntry == null ? generator.generateIntermediate(root) : intermediateEntry;
        KeyStore.PrivateKeyEntry virksomhet = generator.generateVirksomhet("987654321", intermediate, rootCertificate);

        pkcs12.setEntry("root", root, protection);
        pkcs12.setCertificateEntry("rootcert" , root.getCertificate());
        pkcs12.setEntry("intermediate", intermediate, protection);
        pkcs12.setEntry("virksomhet", virksomhet, protection);


        List<String> list = Arrays.asList("974720760", "987464291");
        for(String orgNr : list){
            KeyStore.PrivateKeyEntry tmp = generator.generateVirksomhet(orgNr, intermediate, rootCertificate);
            pkcs12.setEntry(orgNr, tmp, protection);
        }

        KeyStore.PrivateKeyEntry tmp2 = generator.generateVirksomhet("987464291", intermediate, rootCertificate);
        pkcs12.setEntry("987464291_b", tmp2, protection);
        KeyStore.PrivateKeyEntry tmp3 = generator.generateVirksomhet("987464291", intermediate, rootCertificate);
        pkcs12.setEntry("987464291_a", tmp3, protection);

        KeyStore.PrivateKeyEntry revoked = generator.generateVirksomhet("987464291", intermediate, rootCertificate);
        pkcs12.setEntry("revoked", revoked, protection);



        KeyStore.PrivateKeyEntry notvalidYet = generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                rootCertificate,
                generator.standardVirksomhet((X509Certificate) intermediate.getCertificate()),
                DateTime.now().plusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
        pkcs12.setEntry("not-valid-yet", notvalidYet, protection);

        KeyStore.PrivateKeyEntry expired = generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                rootCertificate,
                generator.standardVirksomhet((X509Certificate) intermediate.getCertificate()),
                DateTime.now().minusYears(2).toDate(),
                DateTime.now().minusYears(1).toDate()
        );
        pkcs12.setEntry("expired", expired, protection);

        KeyStore.PrivateKeyEntry no_orgnr= generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat",
                intermediate,
                rootCertificate,
                generator.standardVirksomhet((X509Certificate) intermediate.getCertificate()),
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
        pkcs12.setEntry("no_orgnr", no_orgnr, protection);

        KeyStore.PrivateKeyEntry missing_policy = missingPolicy(generator, intermediate, null);
        pkcs12.setEntry("missing_policy", missing_policy, protection);

        KeyStore.PrivateKeyEntry wrong_policy = wrongPolicy(generator, intermediate, null);
        pkcs12.setEntry("wrong_policy", wrong_policy, protection);

        KeyStore.PrivateKeyEntry not_signed = notSigned(generator, intermediate);
        pkcs12.setEntry("not_signed", not_signed, protection);


        KeyStore.PrivateKeyEntry otherRoot = generator.generateRot();
        KeyStore.PrivateKeyEntry otherIntermediate = generator.generateIntermediate(otherRoot);
        KeyStore.PrivateKeyEntry signed_by_other = generator.generateVirksomhet("987464291",  otherIntermediate, rootCertificate);
        pkcs12.setEntry("signed_by_other", signed_by_other, protection);





        FileOutputStream file = new FileOutputStream("test.jks");
        pkcs12.store(file, password);
        file.close();

        X509v2CRLBuilder builder = new JcaX509v2CRLBuilder((X509Certificate) intermediate.getCertificate(), new Date());
        builder.addCRLEntry(((X509Certificate) revoked.getCertificate()).getSerialNumber(), DateTime.now().minusDays(10).toDate(), 0);

        ContentSigner revocationGen = new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider("BC").build(intermediate.getPrivateKey());
        X509CRLHolder crl = builder.build(revocationGen);
        FileOutputStream crlFile = new FileOutputStream("revoced.crl");
        crlFile.write(crl.getEncoded());
        crlFile.close();


    }

    private KeyStore.PrivateKeyEntry missingPolicy(TestVirksomhetGenerator generator, final KeyStore.PrivateKeyEntry intermediate, Certificate rootCertificate) throws Exception {
        CustomCertBuilder custom = new CustomCertBuilder() {
            @Override
            public void build(X509v3CertificateBuilder certGen, KeyPair keyPair) throws Exception{
                certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier((X509Certificate) intermediate.getCertificate()));
                certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
                certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            }
        };
        return generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                rootCertificate,
                custom,
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
    }

    private KeyStore.PrivateKeyEntry wrongPolicy(TestVirksomhetGenerator generator, final KeyStore.PrivateKeyEntry intermediate, Certificate rootCertificate) throws Exception {
        CustomCertBuilder custom = new CustomCertBuilder() {
            @Override
            public void build(X509v3CertificateBuilder certGen, KeyPair keyPair) throws Exception{
                certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier((X509Certificate) intermediate.getCertificate()));
                certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
                certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

                certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4.5.6"))));
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            }
        };
        return generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                rootCertificate,
                custom,
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
    }

    private KeyStore.PrivateKeyEntry notSigned(TestVirksomhetGenerator generator, final KeyStore.PrivateKeyEntry intermediate) throws Exception {
        CustomCertBuilder custom = new CustomCertBuilder() {
            @Override
            public void build(X509v3CertificateBuilder certGen, KeyPair keyPair) throws Exception{
                certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
                certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

                certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.16.578.1.1.1.1.100"))));
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            }
        };
        return generator.generateSelfSignedGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                custom,
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
    }


    public static void main( String[] args ) throws Exception
    {
        System.out.println("Args length " + args.length);
        for(String s : args){
            System.out.println(" - " + s);
        }

        if(args.length > 0){
            KeyStore pkcs12 = KeyStore.getInstance("JKS");
            char[] password = args[1].toCharArray();
            pkcs12.load(new FileInputStream(args[0]), password);

            KeyStore.PasswordProtection protParam = new KeyStore.PasswordProtection(password);
            KeyStore.PrivateKeyEntry root = (KeyStore.PrivateKeyEntry)pkcs12.getEntry("root", protParam);
            KeyStore.PrivateKeyEntry intermediate = (KeyStore.PrivateKeyEntry)pkcs12.getEntry("intermediate", protParam);
            new App(root, intermediate);
        }else
        {
            new App(null, null);
        }


    }
}
