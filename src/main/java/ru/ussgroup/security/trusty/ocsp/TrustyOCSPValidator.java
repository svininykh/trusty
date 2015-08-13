package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;

import ru.ussgroup.security.trusty.repository.TrustyRepository;

public interface TrustyOCSPValidator {
    OCSPStatusInfo validate(X509Certificate cert) throws OCSPNotAvailableException;
    
    TrustyRepository getRepository();
}
