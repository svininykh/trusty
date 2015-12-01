package ru.ussgroup.security.trusty;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustyCertFormatValidator {
    private final String iin, bin;
    
    private final boolean checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth;

    public TrustyCertFormatValidator(String iin, String bin, boolean checkIsEnterprise, boolean checkIsPersonal, boolean checkForSigning, boolean checkForAuth) {
        this.iin = iin;
        this.bin = bin;
        this.checkIsEnterprise = checkIsEnterprise;
        this.checkIsPersonal = checkIsPersonal;
        this.checkForSigning = checkForSigning;
        this.checkForAuth = checkForAuth;
    }
    
    public void validate(X509Certificate cert) throws CertificateException {
        if (checkForAuth && !TrustyKeyUsageChecker.getKeyUsage(cert).contains(TrustyKeyUsage.AUTHENTICATION)) {
            throw new CertificateException("Certificate is not for auth");
        }
        
        if (checkForSigning && !TrustyKeyUsageChecker.getKeyUsage(cert).contains(TrustyKeyUsage.SIGNING)) {
            throw new CertificateException("Certificate is not for signing");
        }
        
        TrustySubjectDNParser p = new TrustySubjectDNParser(cert.getSubjectDN());
        
        if (iin != null && !p.getIin().equals(iin)) {
            throw new CertificateException("IIN not equals");
        }
        
        if (bin != null && !p.getBin().equals(bin)) {
            throw new CertificateException("BIN not equals");
        }
        
        if (checkIsEnterprise && p.getBin() == null) {
            throw new CertificateException("Certificate not include BIN");
        }
        
        if (checkIsPersonal && p.getBin() != null) {
            throw new CertificateException("Certificate include BIN");
        }
    }
    
    public static class Builder {
        private String iin, bin;
        
        private boolean checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth;
        
        public Builder checkIin(String iin) {
            this.iin = iin;
            return this;
        }
        
        public Builder checkBin(String bin) {
            this.bin = bin;
            return this;
        }
        
        public Builder checkIsEnterprise() {
            this.checkIsEnterprise = true;
            return this;
        }
        
        public Builder checkIsPersonal() {
            this.checkIsPersonal = true;
            return this;
        }
        
        public Builder checkForSigning() {
            this.checkForSigning = true;
            return this;
        }
        
        public Builder checkForAuth() {
            this.checkForAuth = true;
            return this;
        }
        
        public TrustyCertFormatValidator build() {
            return new TrustyCertFormatValidator(iin, bin, checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth);
        }
    }
}
