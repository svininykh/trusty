package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ru.ussgroup.security.trusty.repository.TrustyRepository;

public interface TrustyOCSPValidator {
    CompletableFuture<TrustyOCSPValidationResult> validate(Set<X509Certificate> certs);
    
    TrustyRepository getRepository();
}
