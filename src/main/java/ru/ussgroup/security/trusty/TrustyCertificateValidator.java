package ru.ussgroup.security.trusty;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import ru.ussgroup.security.trusty.ocsp.OCSPNotAvailableException;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

/**
 * This class is thread-safe 
 */
public class TrustyCertificateValidator {
    static {
        boolean exists = false;
    
        for (Provider p : Security.getProviders()) {
            if (p.getName().equals(KalkanProvider.PROVIDER_NAME)) {
                exists = true;
            }
        }
    
        if (!exists) {
            Security.addProvider(new KalkanProvider());
        }
    }
    
    private final TrustyOCSPValidator ocspValidator;
    
    private final TrustyRepository repository;
    
    private final String iin, bin;
    
    private final boolean checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth, disableOCSP;
    
    private final Date date;
    
    private final String provider;
    
    public TrustyCertificateValidator(TrustyOCSPValidator ocspValidator, TrustyRepository repository, String iin, String bin, boolean checkIsEnterprise, 
                                      boolean checkIsPersonal, boolean checkForSigning, boolean checkForAuth, boolean disableOCSP, Date date, String provider) {
        this.ocspValidator = ocspValidator;
        this.repository = repository == null ? ocspValidator.getRepository() : repository;
        this.iin = iin;
        this.bin = bin;
        this.checkIsEnterprise = checkIsEnterprise;
        this.checkIsPersonal = checkIsPersonal;
        this.checkForSigning = checkForSigning;
        this.checkForAuth = checkForAuth;
        this.disableOCSP = disableOCSP;
        this.date = date;
        this.provider = provider;
    }
    
    public void validate(X509Certificate cert) throws CertPathValidatorException, CertificateException {
        List<Certificate> list = new ArrayList<>();
        
        list.add(cert);
        
        X509Certificate current = cert;
        
        while (true) {        
            X509Certificate x509IntermediateCert = repository.getIntermediateCert(current);
            
            if (x509IntermediateCert != null) {
                list.add(x509IntermediateCert);
                
                current = x509IntermediateCert;
            } else {
                break;
            }
        }
        
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(repository.getTrustedCerts().stream().map(c -> new TrustAnchor(c, null)).collect(Collectors.toSet()), null);
            params.setRevocationEnabled(false);
            params.setDate(date);
            params.addCertPathChecker(new PKIXCertPathChecker() {
                @Override
                public boolean isForwardCheckingSupported() {return false;}
                
                @Override
                public void init(boolean forward) throws CertPathValidatorException {}
                
                @Override
                public Set<String> getSupportedExtensions() {return null;}
                
                @Override
                public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
                    try {
                        X509Certificate trustedCert = repository.getTrustedCert((X509Certificate) cert);
                        
                        if (trustedCert != null) {
                            try {
                                trustedCert.checkValidity();
                            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                                throw new CertPathValidatorException(e);
                            }
                        }
                        
                        if (!disableOCSP) {
                            ocspValidator.validate((X509Certificate) cert);
                            
                            if (trustedCert != null) {//проверяем на отозванность доверенный сертификат, который не входит в цепочку доверия
                                ocspValidator.validate(trustedCert);
                            }
                        }
                    } catch (OCSPNotAvailableException e) {
                        throw new CertPathValidatorException(e);
                    }
                }
            });
        
            try {
                if (provider != null) {
                    CertPathValidator.getInstance("PKIX", provider).validate(CertificateFactory.getInstance("X.509", provider).generateCertPath(list), params);
                } else {
                    CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(list), params);
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
            
            SubjectDNParser p = new SubjectDNParser(cert.getSubjectDN().getName());
            
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
        private TrustyOCSPValidator ocspValidator;
        
        private String iin, bin;
        
        private boolean checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth, disableOCSP;
        
        private TrustyRepository repository;
        
        private Date date;
        
        private String provider;
        
        public Builder(TrustyOCSPValidator ocspValidator) {
            this.ocspValidator = ocspValidator;
        }
        
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
        
        public Builder disableOCSP() {
            this.disableOCSP = true;
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
        
        public TrustyCertificateValidator build() {
            return new TrustyCertificateValidator(ocspValidator, repository, iin, bin, checkIsEnterprise, checkIsPersonal, checkForSigning, checkForAuth, disableOCSP, date, provider);
        }
    }
}
