package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;

public class TrustySignatureValidator {
    public TrustySignatureValidator checkIin(String iin) {
        return this;
    }
    
    public TrustySignatureValidator checkBin(String bin) {
        return this;
    }
    
    public TrustySignatureValidator checkIsEnterprise() {
        return this;
    }
    
    public TrustySignatureValidator checkIsPersonal() {
        return this;
    }
    
    public TrustySignatureValidator checkForSigning() {
        return this;
    }
    
    public TrustySignatureValidator checkForAuth() {
        return this;
    }
    
    public TrustySignatureValidator disableOCSP() {
        return this;
    }
    
    public void checkSignature(String data, String signature, X509Certificate certificate) {
        
    }
}
