package no.digdir.eid.certgenerator;


import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.security.KeyPair;

public interface CustomCertBuilder {

    void build(X509v3CertificateBuilder certGen, KeyPair keyPair) throws Exception;

}
