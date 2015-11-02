package ru.ussgroup.security.trusty;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ru.ussgroup.security.trusty.repository.TrustyRepository;

/**
 * This class is thread-safe 
 */
public class TrustyCertPathValidator {
    private final TrustyRepository repository;
    
    private final String iin, bin;
    
    private final boolean checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth;
    
    private final Date date;
    
    private final String provider;
    
    public TrustyCertPathValidator(TrustyRepository repository, String iin, String bin, boolean checkIsEnterprise,  boolean checkIsPersonal, boolean checkForSigning, boolean checkForAuth, Date date, String provider) {
        this.repository = repository;
        this.iin = iin;
        this.bin = bin;
        this.checkIsEnterprise = checkIsEnterprise;
        this.checkIsPersonal = checkIsPersonal;
        this.checkForSigning = checkForSigning;
        this.checkForAuth = checkForAuth;
        this.date = date;
        this.provider = provider;
    }
    
    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validate(Set<X509Certificate> certs) {
        return CompletableFuture.supplyAsync(() -> {
            return certs.parallelStream().collect(Collectors.toConcurrentMap(X509Certificate::getSerialNumber, c -> {
                try {
                    validate(c);
                    
                    return TrustyCertValidationCode.SUCCESS;
                } catch (Exception e) {
                    return TrustyCertValidationCode.CERT_PATH_FAILED;
                }
            }));
        });
    }
        
    public void validate(X509Certificate cert) throws CertPathValidatorException, CertificateException {
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(repository.getTrustedCerts().stream().map(c -> new TrustAnchor(c, null)).collect(Collectors.toSet()), null);
            params.setRevocationEnabled(false);
            params.setDate(date);
        
            try {
                if (provider != null) {
                    CertPathValidator.getInstance("PKIX", provider).validate(CertificateFactory.getInstance("X.509", provider).generateCertPath(TrustyUtils.getCertPath(cert, repository)), params);
                } else {
                    CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(TrustyUtils.getCertPath(cert, repository)), params);
                }
            } catch (NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
            
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
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static class Builder {
        private String iin, bin;
        
        private boolean checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth;
        
        private TrustyRepository repository;
        
        private Date date;
        
        private String provider;
        
        public Builder(TrustyRepository repository) {
            this.repository = repository;
        }

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
        
        public Builder setDate(Date date) {
            this.date = date;
            return this;
        }
        
        public Builder setProvider(String provider) {
            this.provider = provider;
            return this;
        }
        
        public TrustyCertPathValidator build() {
            return new TrustyCertPathValidator(repository, iin, bin, checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth, date, provider);
        }
    }
}
