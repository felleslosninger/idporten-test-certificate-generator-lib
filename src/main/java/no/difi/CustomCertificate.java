package no.difi;

import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public abstract class CustomCertificate {
    protected X509Certificate intermediate;
    public PublicKey publicKey;
    public abstract void addExtensions(X509v3CertificateBuilder certGen) throws Exception;

    public void setIntermediate(X509Certificate intermediate) {
        this.intermediate = intermediate;
    }

    public X509Certificate getIntermediate() {
        return intermediate;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
}

