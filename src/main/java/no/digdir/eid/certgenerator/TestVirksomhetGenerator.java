package no.digdir.eid.certgenerator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.ZonedDateTime;
import java.util.Date;

public class TestVirksomhetGenerator {
    public static final String CRL_PATH = "http://static.dmz.local/vagrant/eid/oppslagstjenesten/revocation.crl";

    static { Security.addProvider(new BouncyCastleProvider());  }

    private final String rsaEncryption = "SHA256withRSAEncryption";
    private final String ecdsaEncryption = "SHA256withECDSA";

    Date from = Date.from(ZonedDateTime.now().minusMonths(1).toInstant());
    Date to = Date.from(ZonedDateTime.now().plusYears(2).toInstant());
    String certificatePolicies = "2.16.578.1.1.1.1.100";

    String rootSubject = "CN=Digdir, OU=Norge, O=DIFI test - 991825827";
    String mellomligendeSubject = "CN=DIFI test virksomhetssertifiat intermediate, SERIALNUMBER=991825827, O=Difi test";
    String anyPolicy = "2.5.29.32.0";

    private static CRLDistPoint crlDistPoint(X500Principal issuer, String... crlPaths) {
        DistributionPoint[] distributionPoints = new DistributionPoint[crlPaths.length];
        for (int i = 0; i < crlPaths.length; i++) {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, crlPaths[i]);
            DistributionPointName distributionPointname = new DistributionPointName(DistributionPointName.FULL_NAME, gn);
            DistributionPoint distributionPoint = new DistributionPoint(
                    distributionPointname,
                    new ReasonFlags(ReasonFlags.keyCompromise),
                    new GeneralNames(new GeneralName(new X500Name(issuer.getName())))
            );
            distributionPoints[i] = distributionPoint;
        }
        return new CRLDistPoint(distributionPoints);
    }

    public static CRLDistPoint createDistributionPointExtention(X509Certificate intermediate) {
        return crlDistPoint(intermediate.getSubjectX500Principal(), CRL_PATH);
    }

    public KeyStore.PrivateKeyEntry generateRot() throws Exception {

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        g.initialize(spec);
        KeyPair keyPair = g.generateKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();

        X500Name issuerName = new X500Name(rootSubject);
        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(RSAPubKey.getEncoded()));

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
                issuerName,
                getRandomBigint(),
                from,
                to,
                new X500Name(rootSubject),
                subjPubKeyInfo
        );

        v3CertGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        v3CertGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createTruncatedSubjectKeyIdentifier(RSAPubKey));


        //Content Signer
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(RSAPrivateKey);
        X509CertificateHolder build = v3CertGen.build(sigGen);

        InputStream byteInStream = new ByteArrayInputStream(build.getEncoded());
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(byteInStream);

        return new KeyStore.PrivateKeyEntry(RSAPrivateKey, new Certificate[]{certificate});
    }

    public KeyStore.PrivateKeyEntry  generateIntermediate(KeyStore.PrivateKeyEntry privateKeyRoot, String crlPath) throws Exception {
        PrivateKey caKey = privateKeyRoot.getPrivateKey();
        X509Certificate caCert = (X509Certificate) privateKeyRoot.getCertificate();

        KeyPair keyPair = getNewKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();


        X500Principal issuer = caCert.getSubjectX500Principal();
        BigInteger serialNo = getRandomBigint();

        X500Principal subject = new X500Principal(mellomligendeSubject);

        X509v3CertificateBuilder certGen =  new JcaX509v3CertificateBuilder(issuer, serialNo, from, to, subject, RSAPubKey);

        certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier(caCert));
        certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(RSAPubKey));
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(anyPolicy))));

        CRLDistPoint crl = crlDistPoint(((X509Certificate) privateKeyRoot.getCertificate()).getSubjectX500Principal(), crlPath);
        certGen.addExtension(Extension.cRLDistributionPoints, false, crl);

        ContentSigner sigGen = contentSigner(caKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        return toKeystoreEntry(RSAPrivateKey, cert);
    }

    public KeyStore.PrivateKeyEntry  generateIntermediate(KeyStore.PrivateKeyEntry privateKeyRoot) throws Exception {
        return generateIntermediate(privateKeyRoot, CRL_PATH);
    }

    public KeyStore.PrivateKeyEntry toKeystoreEntry(PrivateKey RSAPrivateKey, X509CertificateHolder cert) throws IOException, CertificateException {
        InputStream byteInStream = new ByteArrayInputStream(cert.getEncoded());
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(byteInStream);
        return new KeyStore.PrivateKeyEntry(RSAPrivateKey, new Certificate[]{certificate});
    }

    public KeyPair getNewKeyPair() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
        kpGen.initialize(256, random);
        return kpGen.generateKeyPair();
    }

    public KeyStore.PrivateKeyEntry generateVirksomhet(String orgnr, KeyStore.PrivateKeyEntry intermediate) throws Exception {
        return generateVirksomhet(orgnr, intermediate, null, CRL_PATH);
    }

    public KeyStore.PrivateKeyEntry generateVirksomhet(String orgnr, KeyStore.PrivateKeyEntry intermediate, BigInteger serialnumber, String...crlPath) throws Exception {
        KeyPair keyPair = getNewKeyPair();
        X509v3CertificateBuilder builder = builder(orgnr, keyPair.getPublic(), intermediate.getCertificate(), serialnumber);


        GeneralNames subjectAltNames = GeneralNames.getInstance(new DERSequence(new GeneralName(GeneralName.dNSName, "demo-vc-verifier.idporten.dev")));
        builder.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);

        addVirksomhetExtensions(builder, (X509Certificate)intermediate.getCertificate(), keyPair.getPublic(), crlPath);
        ContentSigner sigGen = contentSigner(intermediate.getPrivateKey());
        X509CertificateHolder cert = builder.build(sigGen);
        return toKeystoreEntry(keyPair.getPrivate(), cert);
    }

    public X509v3CertificateBuilder builder(
            String orgnr,
            PublicKey publicKey,
            Certificate intermediateCertificate,
            BigInteger serialnumber
    ) throws NoSuchAlgorithmException {
        return new JcaX509v3CertificateBuilder(
                subject(intermediateCertificate), // issuer = subject of intermediate
                serialnumber == null ? getRandomBigint() : serialnumber,
                from,
                to,
                new X500Principal(createVirksomhetSubject(orgnr)),
                publicKey
        );
    }

    public X500Principal subject(Certificate certificate) {
        return new X500Principal(((X509Certificate)certificate).getSubjectDN().getName());
    }

    public ContentSigner contentSigner(PrivateKey privateKey) throws OperatorCreationException {
        return new JcaContentSignerBuilder(ecdsaEncryption).setProvider("BC").build(privateKey);
    }

    public KeyStore.PrivateKeyEntry generateGenerisk(String subjectText, KeyStore.PrivateKeyEntry intermediate, CustomCertBuilder custom, Date fromDate, Date toDate) throws Exception {

        PrivateKey intermediatePrivateKey = intermediate.getPrivateKey();
        X509Certificate intermediateCertificate = (X509Certificate) intermediate.getCertificate();


        KeyPair keyPair = getNewKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();

        X500Principal issuer = intermediateCertificate.getSubjectX500Principal();
        BigInteger serialNo = getRandomBigint();
        X500Principal subject = new X500Principal(subjectText);

        X509v3CertificateBuilder certGen =  new JcaX509v3CertificateBuilder(issuer, serialNo, fromDate, toDate, subject, RSAPubKey);
        custom.build(certGen, keyPair);
        ContentSigner sigGen = contentSigner(intermediatePrivateKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        return toKeystoreEntry(RSAPrivateKey, cert);
    }

    public KeyStore.PrivateKeyEntry generateSelfSignedGenerisk(String subjectText, CustomCertBuilder custom, Date fromDate, Date toDate) throws Exception {

        KeyPair keyPair = getNewKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();



        X500Principal issuer = new X500Principal(subjectText);
        BigInteger serialNo = getRandomBigint();
        X500Principal subject = new X500Principal(subjectText);

        X509v3CertificateBuilder certGen =  new JcaX509v3CertificateBuilder(issuer, serialNo, fromDate, toDate, subject, RSAPubKey);
        custom.build(certGen, keyPair);
        ContentSigner sigGen = contentSigner(RSAPrivateKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        return toKeystoreEntry(RSAPrivateKey, cert);


    }

    private void addVirksomhetExtensions(X509v3CertificateBuilder builder, X509Certificate intermediateCertificate, PublicKey publicKey, String...crlPaths) throws Exception {
        builder.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier(intermediateCertificate.getPublicKey(), intermediateCertificate.getSubjectX500Principal(), intermediateCertificate.getSerialNumber()));
        builder.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(publicKey));
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

        builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(certificatePolicies))));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        CRLDistPoint crl = crlDistPoint(intermediateCertificate.getSubjectX500Principal(),crlPaths);
        builder.addExtension(Extension.cRLDistributionPoints, false, crl);
    }

    public CustomCertBuilder addVirksomhetExtensions(final X509Certificate intermediateCertificate) throws Exception {
        return (certGen, keyPair) -> addVirksomhetExtensions(certGen, intermediateCertificate, keyPair.getPublic(), CRL_PATH);
    }

    public BigInteger getRandomBigint() {
        return BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));
    }

    private String createVirksomhetSubject(String orgnr) {
        return "CN=Aldersverifiser";
    }
}
