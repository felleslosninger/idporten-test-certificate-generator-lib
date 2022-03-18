package no.digdir.eid.certgenerator;


import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public interface CustomCertBuilder {

    public void build(X509v3CertificateBuilder certGen, KeyPair keyPair) throws Exception;
}
