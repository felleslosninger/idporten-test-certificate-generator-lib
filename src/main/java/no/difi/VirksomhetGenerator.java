package no.difi;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V2AttributeCertificate;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.joda.time.DateTime;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.cert.X509Extension;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;

public class VirksomhetGenerator {
    static { Security.addProvider(new BouncyCastleProvider());  }
    Date from = new DateTime().minusMonths(1).toDate();
    Date to = new DateTime().plusYears(2).toDate();



    public KeyStore.PrivateKeyEntry generateRot() throws Exception {
        KeyPair keyPair = getKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();

        String subject = "CN=Direktoratet for forvaltning og ikt DIFI TEST, OU=Norge, O=DIFI test - 991825827";
        X500Name issuerName = new X500Name(subject);
        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(RSAPubKey.getEncoded()));

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
                issuerName,
                BigInteger.valueOf(Math.abs(new SecureRandom().nextInt())),
                from,
                to,
                new X500Name(subject),
                subjPubKeyInfo
        );

        v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));


        //Content Signer
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(RSAPrivateKey);

        X509CertificateHolder build = v3CertGen.build(sigGen);
        InputStream byteInStream = new ByteArrayInputStream(build.getEncoded());
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(byteInStream);

        return new KeyStore.PrivateKeyEntry(RSAPrivateKey, new Certificate[]{certificate});
    }

    public KeyStore.PrivateKeyEntry  generateIntermediate(KeyStore.PrivateKeyEntry privateKeyRoot) throws Exception
    {

        PrivateKey caKey = privateKeyRoot.getPrivateKey();
        X509Certificate caCert = (X509Certificate) privateKeyRoot.getCertificate();

        KeyPair keyPair = getKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();


        X500Principal issuer = caCert.getSubjectX500Principal();
        BigInteger serialNo = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));
        X500Principal subject = new X500Principal("CN=DIFI test virksomhetssertifiat intermediate, SERIALNUMBER=991825827");

        X509v3CertificateBuilder certGen =  new JcaX509v3CertificateBuilder(issuer, serialNo, from, to, subject, RSAPubKey);

        certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier(caCert));
        certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(RSAPubKey));
        certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSAEncryption").setProvider("BC").build(caKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        LinkedList<Certificate> list = new LinkedList<Certificate>();
        list.add(caCert);
        return toKeystoreEntry(list, RSAPrivateKey, cert);

    }

    private KeyStore.PrivateKeyEntry toKeystoreEntry(LinkedList<Certificate> signers, PrivateKey RSAPrivateKey, X509CertificateHolder cert) throws IOException, CertificateException {
        InputStream byteInStream = new ByteArrayInputStream(cert.getEncoded());
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(byteInStream);

        signers.add(0, certificate);

        return new KeyStore.PrivateKeyEntry(RSAPrivateKey, signers.toArray(new Certificate[signers.size()]));
    }

    private KeyPair getKeyPair() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(4096, random);
        return kpGen.generateKeyPair();
    }

    public KeyStore.PrivateKeyEntry generateVirksomhet(String orgnr, KeyStore.PrivateKeyEntry intermediate) throws Exception {

        PrivateKey intermediatePrivateKey = intermediate.getPrivateKey();
        X509Certificate intermediateCertificate = (X509Certificate) intermediate.getCertificate();


        KeyPair keyPair = getKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();



        X500Principal issuer = intermediateCertificate.getSubjectX500Principal();
        BigInteger serialNo = BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));
        X500Principal subject = new X500Principal("CN=DIFI test virksomhetssertifiat, SERIALNUMBER=" + orgnr);

        X509v3CertificateBuilder certGen =  new JcaX509v3CertificateBuilder(issuer, serialNo, from, to, subject, RSAPubKey);

        certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier(intermediateCertificate));
        certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(RSAPubKey));
        certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.16.578.1.1.1.1.100"))));
        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSAEncryption").setProvider("BC").build(intermediatePrivateKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        LinkedList<Certificate> list = new LinkedList<Certificate>();
        list.add(intermediateCertificate);
        return toKeystoreEntry(list, RSAPrivateKey, cert);


    }
}
