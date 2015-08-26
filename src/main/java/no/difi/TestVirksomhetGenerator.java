package no.difi;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;

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
import java.util.Date;
import java.util.LinkedList;
import java.security.cert.Certificate;

public class TestVirksomhetGenerator {
    static { Security.addProvider(new BouncyCastleProvider());  }


    public static final String CRL_PATH = "http://deb.difi.local/vagrant/eid/oppslagstjenesten/revocation.crl";
    private final String rsaEncryption = "SHA256withRSAEncryption";
    Date from = new DateTime().minusMonths(1).toDate();
    Date to = new DateTime().plusYears(2).toDate();
    String certificatePolicies = "2.16.578.1.1.1.1.100";

    String rootSubject = "CN=Direktoratet for forvaltning og ikt DIFI TEST ROOT, OU=Norge, O=DIFI test - 991825827";
    String mellomligendeSubject = "CN=DIFI test virksomhetssertifiat intermediate, SERIALNUMBER=991825827, O=Difi test";
    String anyPolicy = "2.5.29.32.0";


    public KeyStore.PrivateKeyEntry generateRot() throws Exception {

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(4096, random);
        KeyPair keyPair = kpGen.generateKeyPair();
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

        CRLDistPoint crl = TestVirksomhetGenerator.createDistributionPointExtention((X509Certificate) privateKeyRoot.getCertificate());
        certGen.addExtension(Extension.cRLDistributionPoints, false, crl);

        ContentSigner sigGen = new JcaContentSignerBuilder(rsaEncryption).setProvider("BC").build(caKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        LinkedList<Certificate> list = new LinkedList<Certificate>();
        list.add(caCert);
        return toKeystoreEntry(list, RSAPrivateKey, cert);

    }




    private KeyStore.PrivateKeyEntry toKeystoreEntry(LinkedList<Certificate> signers, PrivateKey RSAPrivateKey, X509CertificateHolder cert) throws IOException, CertificateException {
        InputStream byteInStream = new ByteArrayInputStream(cert.getEncoded());
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(byteInStream);

        signers.clear();
        signers.add(certificate);

        return new KeyStore.PrivateKeyEntry(RSAPrivateKey, signers.toArray(new Certificate[signers.size()]));
    }

    public KeyPair getNewKeyPair() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048, random);
        return kpGen.generateKeyPair();
    }

    public KeyStore.PrivateKeyEntry generateVirksomhet(String orgnr, KeyStore.PrivateKeyEntry intermediate, X509Certificate rootCertificate) throws Exception {
        return generateVirksomhet(orgnr, intermediate, rootCertificate, null);
    }
    public KeyStore.PrivateKeyEntry generateVirksomhet(String orgnr, KeyStore.PrivateKeyEntry intermediate, X509Certificate rootCertificate, BigInteger serialnumber) throws Exception {

        PrivateKey intermediatePrivateKey = intermediate.getPrivateKey();
        X509Certificate intermediateCertificate = (X509Certificate) intermediate.getCertificate();

        KeyPair keyPair = getNewKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();



        X500Principal issuer = new X500Principal(intermediateCertificate.getSubjectDN().getName());
        System.out.println(issuer);
        BigInteger serialNo = serialnumber == null ? getRandomBigint() : serialnumber;
        X500Principal subject = new X500Principal(createVirksomhetSubject(orgnr));

        X509v3CertificateBuilder certGen =  new JcaX509v3CertificateBuilder(issuer, serialNo, from, to, subject, RSAPubKey);
        standardVirksomhet(intermediateCertificate).build(certGen, keyPair);

        ContentSigner sigGen = new JcaContentSignerBuilder(rsaEncryption).setProvider("BC").build(intermediatePrivateKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        LinkedList<Certificate> list = new LinkedList<Certificate>();

        list.add(intermediateCertificate);
        return toKeystoreEntry(list, RSAPrivateKey, cert);


    }

    public KeyStore.PrivateKeyEntry generateGenerisk(String subjectText, KeyStore.PrivateKeyEntry intermediate, Certificate rootCertificate, CustomCertBuilder custom, Date fromDate, Date toDate) throws Exception {

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
        ContentSigner sigGen = new JcaContentSignerBuilder(rsaEncryption).setProvider("BC").build(intermediatePrivateKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        LinkedList<Certificate> list = new LinkedList<Certificate>();

        list.add(intermediateCertificate);
        return toKeystoreEntry(list, RSAPrivateKey, cert);


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
        ContentSigner sigGen = new JcaContentSignerBuilder(rsaEncryption).setProvider("BC").build(RSAPrivateKey);
        X509CertificateHolder cert = certGen.build(sigGen);

        LinkedList<Certificate> list = new LinkedList<Certificate>();
        return toKeystoreEntry(list, RSAPrivateKey, cert);


    }

    public CustomCertBuilder standardVirksomhet(final X509Certificate intermediateCertificate) throws Exception {
        return new CustomCertBuilder() {
            @Override
            public void build(X509v3CertificateBuilder certGen, KeyPair keyPair) throws Exception{
                certGen.addExtension(Extension.authorityKeyIdentifier, false, (new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier(intermediateCertificate.getPublicKey(), intermediateCertificate.getSubjectX500Principal(), intermediateCertificate.getSerialNumber()));
                certGen.addExtension(Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
                certGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

                certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(certificatePolicies))));
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

                CRLDistPoint crl = createDistributionPointExtention(intermediateCertificate);
                certGen.addExtension(Extension.cRLDistributionPoints, false, crl);
            }
        };
    }

    public static CRLDistPoint createDistributionPointExtention(X509Certificate intermediate) {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, CRL_PATH);
        DistributionPointName distributionPointname = new DistributionPointName(DistributionPointName.FULL_NAME, gn);

        DistributionPoint distributionPoint = new DistributionPoint(
                distributionPointname,
                new ReasonFlags(ReasonFlags.keyCompromise),
                new GeneralNames(new GeneralName(new X509Name((intermediate).getSubjectX500Principal().getName()))));

        DistributionPoint[] points = new DistributionPoint[]{distributionPoint};
        return new CRLDistPoint(points);
    }

    private BigInteger getRandomBigint() {
        return BigInteger.valueOf(Math.abs(new SecureRandom().nextInt()));
    }

    private String createVirksomhetSubject(String orgnr) {
        return "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=" + orgnr;
    }
}
