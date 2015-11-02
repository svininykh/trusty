package ru.ussgroup.security.trusty.utils;

import java.security.cert.X509Certificate;

import ru.ussgroup.security.trusty.TrustyCertValidationCode;

public class SignedData {
    private byte[] data;
    
    private byte[] signature;
    
    private X509Certificate cert;
    
    private boolean valid = true;
    
    private TrustyCertValidationCode certStatus;

    public SignedData(byte[] data, byte[] signature, X509Certificate cert) {
        this.data = data;
        this.signature = signature;
        this.cert = cert;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getSignature() {
        return signature;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public TrustyCertValidationCode getCertStatus() {
        return certStatus;
    }

    public void setCertStatus(TrustyCertValidationCode certStatus) {
        this.certStatus = certStatus;
    }
}
