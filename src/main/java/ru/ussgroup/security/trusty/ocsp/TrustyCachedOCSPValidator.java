package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import ru.ussgroup.security.trusty.repository.TrustyRepository;

public class TrustyCachedOCSPValidator implements TrustyOCSPValidator {
    private final Cache<String, OCSPStatusInfo> certificateStatusCache;
    
    private final Cache<String, OCSPStatusInfo> trustedCertificateStatusCache;
    
    private final TrustyOCSPValidator validator;
    
    public TrustyCachedOCSPValidator(TrustyOCSPValidator validator, int cachedTime, int trustedCachedTime) {
        this.validator = validator;
        certificateStatusCache = CacheBuilder.newBuilder().maximumSize(50_000)
                                                          .expireAfterWrite(cachedTime, TimeUnit.MINUTES)
                                                          .build();
        
        trustedCertificateStatusCache = CacheBuilder.newBuilder().maximumSize(1_000)
                                                                 .expireAfterWrite(trustedCachedTime, TimeUnit.MINUTES)
                                                                 .build();
    }
    
    @Override
    public OCSPStatusInfo validate(X509Certificate cert) throws OCSPNotAvailableException {
        for (X509Certificate c : validator.getRepository().getTrustedCerts()) {
            if (c.getSerialNumber().equals(cert.getSerialNumber())) {            
                return checkInCache(cert, trustedCertificateStatusCache);
            }
        }
        
        for (X509Certificate c : validator.getRepository().getIntermediateCerts()) {
            if (c.getSerialNumber().equals(cert.getSerialNumber())) {            
                return checkInCache(cert, trustedCertificateStatusCache);
            }
        }
        
        return checkInCache(cert, certificateStatusCache);
    }

    private OCSPStatusInfo checkInCache(X509Certificate cert, Cache<String, OCSPStatusInfo> cache) throws OCSPNotAvailableException {
        OCSPStatusInfo status = cache.getIfPresent(cert.getSerialNumber().toString());

        if (status == null) {
            status = validator.validate(cert);
            
            cache.put(cert.getSerialNumber().toString(), status);
        }
        
        return status;
    }

    @Override
    public TrustyRepository getRepository() {
        return validator.getRepository();
    }
}
