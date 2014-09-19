package no.difi;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Date;

public class VirksomhetGenerator {
    static { Security.addProvider(new BouncyCastleProvider());  }



    public KeyStore.PrivateKeyEntry generateRot() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(4096, random);
        KeyPair keyPair = kpGen.generateKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();

        X500Name issuerName = new X500Name("CN=Direktoratet for forvaltning og ikt DIFI, OU=Norge, O=DIFI - 991825827, L=None, C=None");

        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(RSAPubKey.getEncoded()));


        Date from = new DateTime().minusMonths(1).toDate();
        Date to = new DateTime().plusYears(2).toDate();
        String subject = "CN=Direktoratet for forvaltning og ikt DIFI, OU=Norge, O=DIFI - 991825827, L=None, C=None";
        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
                issuerName,
                BigInteger.valueOf(Math.abs(new SecureRandom().nextInt())),
                from,
                to,
                new X500Name(subject),
                subjPubKeyInfo
        );


        //Content Signer
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(RSAPrivateKey);


        X509Certificate bc = new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(sigGen));

        return new KeyStore.PrivateKeyEntry(RSAPrivateKey, new Certificate[]{bc});


    }

    public KeyStore.PrivateKeyEntry generateIntermediate() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(4096, random);
        KeyPair keyPair = kpGen.generateKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();




        return new KeyStore.PrivateKeyEntry(RSAPubKey, new Certificate[]{root});
    }

    public void generateVirksomhet(String orgnr) {

    }
}
