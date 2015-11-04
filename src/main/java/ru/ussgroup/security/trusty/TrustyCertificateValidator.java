package ru.ussgroup.security.trusty;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ru.ussgroup.security.trusty.ocsp.TrustyOCSPStatus;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidationResult;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;

/**
 * This class is thread-safe 
 */
public class TrustyCertificateValidator {
    private TrustyCertPathValidator certPathValidator;
    
    private TrustyOCSPValidator ocspValidator;

    public TrustyCertificateValidator(TrustyCertPathValidator certPathValidator, TrustyOCSPValidator ocspValidator) {
        this.certPathValidator = certPathValidator;
        this.ocspValidator = ocspValidator;
    }

    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validate(Set<X509Certificate> certs) {
        Set<X509Certificate> fullList = new HashSet<>();
        
        Map<BigInteger, List<X509Certificate>> serial2Path = new HashMap<>();
        
        for (X509Certificate cert : certs) {
            List<X509Certificate> fullCertPath = TrustyUtils.getFullCertPath(cert, ocspValidator.getRepository());
            
            fullList.addAll(fullCertPath);
            
            serial2Path.put(cert.getSerialNumber(), fullCertPath);
        }
        
        CompletableFuture<Map<BigInteger, TrustyOCSPStatus>> ocspFuture = ocspValidator.validate(fullList).thenApply(TrustyOCSPValidationResult::getStatuses);
        
        CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> certPathFuture = certPathValidator.validate(certs);
        
        return certPathFuture.thenCombine(ocspFuture, (certPathRes, ocspRes) -> {
            for (Entry<BigInteger, TrustyCertValidationCode> e : certPathRes.entrySet()) {
                if (e.getValue() == TrustyCertValidationCode.SUCCESS) {
                    for (X509Certificate cert : serial2Path.get(e.getKey())) {
                        if (ocspRes.get(cert.getSerialNumber()).getStatus() != TrustyOCSPStatus.GOOD) {//какой-то сертификат из цепочки не прошел проверку OCSP
                            e.setValue(TrustyCertValidationCode.OCSP_FAILED);
                            break;
                        }
                    }
                }
            }
            
            return certPathRes;
        });
    }
}
