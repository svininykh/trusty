package ru.ussgroup.security.trusty;

import java.math.BigInteger;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

public class TrustyAsyncCertPathValidator {
    private TrustyCertPathValidator certPathValidator;
    
    public TrustyAsyncCertPathValidator(TrustyCertPathValidator certPathValidator) {
        this.certPathValidator = certPathValidator;
    }

    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validate(Set<X509Certificate> certs) {
        return CompletableFuture.supplyAsync(() -> {
            return certs.parallelStream().collect(Collectors.toConcurrentMap(X509Certificate::getSerialNumber, c -> {
                try {
                    certPathValidator.validate(c);
                    
                    return TrustyCertValidationCode.SUCCESS;
                } catch (CertificateException | CertPathValidatorException e) {
                    return TrustyCertValidationCode.CERT_PATH_FAILED;
                }
            }));
        });
    }
}
