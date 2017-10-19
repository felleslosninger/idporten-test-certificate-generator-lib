package no.difi.kontaktinfo;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class App {

    public App(KeyStore.PrivateKeyEntry rootEntry, KeyStore.PrivateKeyEntry intermediateEntry) throws Exception {
        KeyStore pkcs12 = KeyStore.getInstance("JKS");
        char[] password = "changeit".toCharArray();
        pkcs12.load(null, password);

        TestVirksomhetGenerator generator = new TestVirksomhetGenerator();
        KeyStore.PrivateKeyEntry root = rootEntry == null ? generator.generateRot() : rootEntry;

        KeyStore.PrivateKeyEntry intermediate = intermediateEntry == null ? generator.generateIntermediate(root) : intermediateEntry;
        KeyStore.PrivateKeyEntry virksomhet = generator.generateVirksomhet("987654321", intermediate);

        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password);
        pkcs12.setEntry("root", root, protection);
        pkcs12.setCertificateEntry("rootcert" , root.getCertificate());
        pkcs12.setEntry("intermediate", intermediate, protection);
        pkcs12.setEntry("virksomhet", virksomhet, protection);


        List<String> list = Arrays.asList("974720760", "987464291");
        for(String orgNr : list){
            KeyStore.PrivateKeyEntry tmp = generator.generateVirksomhet(orgNr, intermediate);
            pkcs12.setEntry(orgNr, tmp, protection);
        }

        KeyStore.PrivateKeyEntry tmp2 = generator.generateVirksomhet("987464291", intermediate);
        pkcs12.setEntry("987464291_b", tmp2, protection);
        KeyStore.PrivateKeyEntry tmp3 = generator.generateVirksomhet("987464291", intermediate);
        pkcs12.setEntry("987464291_a", tmp3, protection);

        KeyStore.PrivateKeyEntry revoked = generator.generateVirksomhet("987464291", intermediate, new BigInteger("7eeea5df", 16), TestVirksomhetGenerator.CRL_PATH);
        pkcs12.setEntry("revoked", revoked, protection);





        KeyStore.PrivateKeyEntry notvalidYet = generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                generator.addVirksomhetExtensions((X509Certificate) intermediate.getCertificate()),
                DateTime.now().plusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
        pkcs12.setEntry("not-valid-yet", notvalidYet, protection);

        KeyStore.PrivateKeyEntry expired = generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                generator.addVirksomhetExtensions((X509Certificate) intermediate.getCertificate()),
                DateTime.now().minusYears(2).toDate(),
                DateTime.now().minusYears(1).toDate()
        );
        pkcs12.setEntry("expired", expired, protection);

        KeyStore.PrivateKeyEntry no_orgnr= generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat",
                intermediate,
                generator.addVirksomhetExtensions((X509Certificate) intermediate.getCertificate()),
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
        pkcs12.setEntry("no_orgnr", no_orgnr, protection);

        KeyStore.PrivateKeyEntry missing_policy = missingPolicy(generator, intermediate);
        pkcs12.setEntry("missing_policy", missing_policy, protection);

        KeyStore.PrivateKeyEntry wrong_policy = wrongPolicy(generator, intermediate);
        pkcs12.setEntry("wrong_policy", wrong_policy, protection);

        KeyStore.PrivateKeyEntry not_signed = notSigned(generator, intermediate);
        pkcs12.setEntry("not_signed", not_signed, protection);

        KeyStore.PrivateKeyEntry missing_distribution_point = missingDistributionPoint(generator, intermediate);
        pkcs12.setEntry("missing_distribution_point", missing_distribution_point, protection);

        KeyStore.PrivateKeyEntry unavailable_distribution_point = unavailableDistributionPoint(generator, intermediate);
        pkcs12.setEntry("unavailable_distribution_point", unavailable_distribution_point , protection);



        KeyStore.PrivateKeyEntry otherRoot = generator.generateRot();
        KeyStore.PrivateKeyEntry otherIntermediate = generator.generateIntermediate(otherRoot);
        KeyStore.PrivateKeyEntry signed_by_other = generator.generateVirksomhet("987464291",  otherIntermediate);
        pkcs12.setEntry("signed_by_other", signed_by_other, protection);





        FileOutputStream file = new FileOutputStream("test.jks");
        pkcs12.store(file, password);
        file.close();

        X509Certificate certificate = (X509Certificate) revoked.getCertificate();
        createCrlList(intermediate, certificate);


    }


    private void createCrlList(KeyStore.PrivateKeyEntry intermediate, X509Certificate certificate) throws OperatorCreationException, IOException {
        X509v2CRLBuilder builder = new JcaX509v2CRLBuilder((X509Certificate) intermediate.getCertificate(), new Date());
        builder.addCRLEntry(certificate.getSerialNumber(), DateTime.now().minusDays(10).toDate(), 0);

        ContentSigner revocationGen = new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider("BC").build(intermediate.getPrivateKey());
        X509CRLHolder crl = builder.build(revocationGen);
        FileOutputStream crlFile = new FileOutputStream("revoced.crl");
        crlFile.write(crl.getEncoded());
        crlFile.close();
    }

    private KeyStore.PrivateKeyEntry unavailableDistributionPoint(TestVirksomhetGenerator generator, final KeyStore.PrivateKeyEntry intermediate) throws Exception {
        CustomCertBuilder custom = (certGen, keyPair) -> {
            certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier((X509Certificate) intermediate.getCertificate()));
            certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
            certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.16.578.1.1.1.1.100"))));

            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, TestVirksomhetGenerator.CRL_PATH + "not_existing") ;
            DistributionPointName distributionPointname = new DistributionPointName(DistributionPointName.FULL_NAME, gn);

            DistributionPoint distributionPoint = new DistributionPoint(
                    distributionPointname,
                    new ReasonFlags(ReasonFlags.keyCompromise),
                    new GeneralNames(new GeneralName(new X500Name(((X509Certificate)intermediate.getCertificate()).getSubjectX500Principal().getName()))));

            DistributionPoint[] points = new DistributionPoint[]{distributionPoint};
            CRLDistPoint crl = new CRLDistPoint(points);
            certGen.addExtension(Extension.cRLDistributionPoints, false, crl);
        };


        return generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                custom,
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
    }

    private KeyStore.PrivateKeyEntry missingDistributionPoint(TestVirksomhetGenerator generator, final KeyStore.PrivateKeyEntry intermediate) throws Exception {
        CustomCertBuilder custom = (certGen, keyPair) -> {
            certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier((X509Certificate) intermediate.getCertificate()));
            certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
            certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.16.578.1.1.1.1.100"))));

            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        };


        return generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                custom,
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
    }

    private KeyStore.PrivateKeyEntry missingPolicy(TestVirksomhetGenerator generator, final KeyStore.PrivateKeyEntry intermediate) throws Exception {
        CustomCertBuilder custom = (certGen, keyPair) -> {
            certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier((X509Certificate) intermediate.getCertificate()));
            certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
            certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            CRLDistPoint crl = TestVirksomhetGenerator.createDistributionPointExtention((X509Certificate)intermediate.getCertificate());
            certGen.addExtension(Extension.cRLDistributionPoints, false, crl);
        };


        return generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                custom,
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
    }



    private KeyStore.PrivateKeyEntry wrongPolicy(TestVirksomhetGenerator generator, final KeyStore.PrivateKeyEntry intermediate) throws Exception {
        CustomCertBuilder custom = (certGen, keyPair) -> {
            certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier((X509Certificate) intermediate.getCertificate()));
            certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
            certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

            certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4.5.6"))));
            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            CRLDistPoint crl = TestVirksomhetGenerator.createDistributionPointExtention((X509Certificate)intermediate.getCertificate());
            certGen.addExtension(Extension.cRLDistributionPoints, false, crl);
        };
        return generator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                intermediate,
                custom,
                DateTime.now().minusYears(1).toDate(),
                DateTime.now().plusYears(2).toDate()
        );
    }

    private KeyStore.PrivateKeyEntry notSigned(TestVirksomhetGenerator generator, final KeyStore.PrivateKeyEntry intermediate) throws Exception {
        CustomCertBuilder custom = (certGen, keyPair) -> {
            certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
            certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

            certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.16.578.1.1.1.1.100"))));
            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            CRLDistPoint crl = TestVirksomhetGenerator.createDistributionPointExtention((X509Certificate)intermediate.getCertificate());
            certGen.addExtension(Extension.cRLDistributionPoints, false, crl);
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
