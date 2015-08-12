package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;

public interface TrustyOCSPValidator {
    OCSPStatusInfo validate(X509Certificate cert) throws OCSPNotAvailableException;
}
