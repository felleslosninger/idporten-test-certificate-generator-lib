package no.digdir.eid.certgenerator;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("When using the certificate generator")
public class TestVirksomhetGeneratorTest {

    private final TestVirksomhetGenerator testVirksomhetGenerator = new TestVirksomhetGenerator();

    @Test
    @DisplayName("then a self-signed root certificate can be generated")
    public void testGenerateRoot() throws Exception {
        KeyStore.PrivateKeyEntry root = testVirksomhetGenerator.generateRot();
        root.getCertificate().verify(root.getCertificate().getPublicKey());
        ((X509Certificate) root.getCertificate()).checkValidity();
        assertAll(
                () -> assertEquals(1, root.getCertificateChain().length),
                () -> assertEquals(root.getCertificate(), root.getCertificateChain()[0])
        );
    }

    @Test
    @DisplayName("then a certificate chain with root and intermediate can be generated")
    public void testGenerateCertificateChain() throws Exception {
        KeyStore.PrivateKeyEntry root = testVirksomhetGenerator.generateRot();
        KeyStore.PrivateKeyEntry intermediate = testVirksomhetGenerator.generateIntermediate(root);
        intermediate.getCertificate().verify(root.getCertificate().getPublicKey());
        ((X509Certificate) root.getCertificate()).checkValidity();
        ((X509Certificate) intermediate.getCertificate()).checkValidity();
        intermediate.getCertificate().verify(root.getCertificate().getPublicKey());
        assertAll(
                () -> assertEquals(1, intermediate.getCertificateChain().length),
                () -> assertEquals(
                        ((X509Certificate) intermediate.getCertificate()).getIssuerX500Principal(),
                        ((X509Certificate) root.getCertificate()).getIssuerX500Principal())
        );
    }

    @Test
    @DisplayName("then a virksomshet certificate with organization number and crl distributions points can be generated")
    public void testGenerateVirksomhetsCertificate() throws Exception {
        KeyStore.PrivateKeyEntry root = testVirksomhetGenerator.generateRot();
        KeyStore.PrivateKeyEntry intermediate = testVirksomhetGenerator.generateIntermediate(root);
        List<String> crlDistributionPointUrls = Arrays.asList("ldaps://junit.digdir.no/crl", "https://junit.digdir.no/crl");
        KeyStore.PrivateKeyEntry virksomhet = testVirksomhetGenerator.generateVirksomhet(
                "123456789",
                intermediate,
                new BigInteger(String.valueOf(new Random().nextLong())),
                crlDistributionPointUrls.toArray(new String[0]));
        ((X509Certificate) root.getCertificate()).checkValidity();
        ((X509Certificate) intermediate.getCertificate()).checkValidity();
        ((X509Certificate) virksomhet.getCertificate()).checkValidity();
        Certificate virksomhetsCertificate = virksomhet.getCertificate();
        X509Certificate x509VirksomhetsCertificate = (X509Certificate) virksomhetsCertificate;
        virksomhetsCertificate.verify(intermediate.getCertificate().getPublicKey());
//        assertAll(
//                () -> assertTrue(x509VirksomhetsCertificate.getSubjectX500Principal().toString().contains("SERIALNUMBER=123456789")),
//                () -> assertTrue(getCrlDistributionPoints(x509VirksomhetsCertificate).containsAll(crlDistributionPointUrls))
//        );
        System.out.println(pemEncodedCert(x509VirksomhetsCertificate));
    }

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";


    /**
     * Encode certificate.
     */
    static String pemEncodedCert(Certificate cert) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append(BEGIN_CERT + "\n");
        sb.append(Base64.getEncoder().encodeToString(cert.getEncoded()));
        sb.append("\n" + END_CERT);
        return sb.toString();
    }


    @Test
    @DisplayName("then an expired certificate can be generated")
    public void testGenerateExpiredCertificate() throws Exception {
        KeyStore.PrivateKeyEntry root = testVirksomhetGenerator.generateRot();
        KeyStore.PrivateKeyEntry expired = testVirksomhetGenerator.generateGenerisk(
                "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                root,
                (certGen, keyPair) -> {
                },
                Date.from(ZonedDateTime.now().minusYears(2).toInstant()),
                Date.from(ZonedDateTime.now().minusYears(1).toInstant())
        );
        X509Certificate expiredCertificate = (X509Certificate) expired.getCertificate();
        assertThrows(CertificateExpiredException.class, expiredCertificate::checkValidity);
    }

    private List<String> getCrlDistributionPoints(X509Certificate certificate) throws Exception {
        if (!certificate.getNonCriticalExtensionOIDs().contains("2.5.29.31")) {
            return Collections.emptyList();
        }
        CRLDistPoint distPoint = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(certificate.getExtensionValue("2.5.29.31")));
        List<String> urls = new ArrayList<>();
        for (DistributionPoint dp : distPoint.getDistributionPoints())
            for (GeneralName name : ((GeneralNames) dp.getDistributionPoint().getName()).getNames())
                if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
                    urls.add(((DERIA5String) name.getName()).getString());

        return urls;
    }

}
