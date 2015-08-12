package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;
import java.util.Collection;

public interface TrustyRepository {
    Collection<X509Certificate> getTrustedCerts();
    
    X509Certificate getIntermediateCert(X509Certificate cert);
    
    X509Certificate getIssuer(X509Certificate cert);
}
