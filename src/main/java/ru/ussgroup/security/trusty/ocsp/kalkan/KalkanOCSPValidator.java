package ru.ussgroup.security.trusty.ocsp.kalkan;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import kz.gov.pki.kalkan.ocsp.OCSPResp;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidationResult;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

/**
 * This class is thread-safe
 */
public class KalkanOCSPValidator implements TrustyOCSPValidator {
    private final KalkanOCSPRequestSender kalkanOCSPRequestSender;
    
    private final KalkanOCSPResponseChecker kalkanOCSPResponseChecker;
    
    public KalkanOCSPValidator(String ocspUrl, TrustyRepository trustyRepository) {
        kalkanOCSPRequestSender = new KalkanOCSPRequestSender(ocspUrl, trustyRepository);
        kalkanOCSPResponseChecker = new KalkanOCSPResponseChecker(trustyRepository);
    }
    
    @Override
    public CompletableFuture<TrustyOCSPValidationResult> validate(Set<X509Certificate> certs) {
        KalkanOCSPResponse r = kalkanOCSPRequestSender.sendRequest(certs);

        return r.getFutureResponse().thenApplyAsync((OCSPResp ocspResp) -> {//проверяем асинхронно, т.к. checkResponse тяжелый метод из-за проверки сертификата OCSP
            try {
                return kalkanOCSPResponseChecker.checkResponse(ocspResp, r.getNonce());
            } catch (TrustyOCSPNonceException | CertificateException | CertPathValidatorException e) {
                throw new SecurityException(e);
            }
        });
    }

    @Override
    public TrustyRepository getRepository() {
        return kalkanOCSPRequestSender.getRepository();
    }
}
