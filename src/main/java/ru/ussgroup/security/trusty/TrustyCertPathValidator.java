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
    
    private final String provider;
    
    public TrustyCertPathValidator(TrustyRepository repository, String provider) {
        this.repository = repository;
        this.provider = provider;
    }
    
    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validateAsync(Set<X509Certificate> certs) {
        return validateAsync(certs, new Date());
    }
    
    /**
     * @param date null is disable expire date verification
     */
    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validateAsync(Set<X509Certificate> certs, Date date) {
        return CompletableFuture.supplyAsync(() -> {
            return certs.parallelStream().collect(Collectors.toConcurrentMap(X509Certificate::getSerialNumber, c -> {
                try {
                    validate(c, date);
                    
                    return TrustyCertValidationCode.SUCCESS;
                } catch (Exception e) {
                    return TrustyCertValidationCode.CERT_PATH_FAILED;
                }
            }));
        });
    }
    
    public void validate(X509Certificate cert) throws CertPathValidatorException, CertificateException {
        validate(cert, new Date());
    }
        
    /**
     * @param date null is disable expire date verification
     */
    public void validate(X509Certificate cert, Date date) throws CertPathValidatorException, CertificateException {
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(repository.getTrustedCerts().stream().map(c -> new TrustAnchor(c, null)).collect(Collectors.toSet()), null);
            params.setRevocationEnabled(false);
            
            params.setDate(date != null ? date : cert.getNotBefore());
        
            try {
                if (provider != null) {
                    CertPathValidator.getInstance("PKIX", provider).validate(CertificateFactory.getInstance("X.509", provider).generateCertPath(TrustyUtils.getCertPath(cert, repository)), params);
                } else {
                    CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(TrustyUtils.getCertPath(cert, repository)), params);
                }
            } catch (NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }
}
