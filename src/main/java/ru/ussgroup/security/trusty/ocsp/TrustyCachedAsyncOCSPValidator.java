package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import ru.ussgroup.security.trusty.TrustyRepository;

public class TrustyCachedAsyncOCSPValidator implements TrustyOCSPValidator {
    private Cache<String, OCSPStatusInfo> certificateStatusCache;
    
    private TrustyOCSPValidator validator;
    
    public TrustyCachedAsyncOCSPValidator(TrustyOCSPValidator validator, TrustyRepository trustyRepository, int cachedTime) {
        certificateStatusCache = CacheBuilder.newBuilder().maximumSize(50_000)
                                                          .expireAfterWrite(cachedTime, TimeUnit.MINUTES)
                                                          .build();
    }
    
    @Override
    public OCSPStatusInfo validate(X509Certificate cert) throws OCSPNotAvailableException {
        OCSPStatusInfo status = certificateStatusCache.getIfPresent(cert.getSerialNumber().toString());

        if (status == null) {
            status = validator.validate(cert);
            
            certificateStatusCache.put(cert.getSerialNumber().toString(), status);
        }
        
        return status;
    }
}
