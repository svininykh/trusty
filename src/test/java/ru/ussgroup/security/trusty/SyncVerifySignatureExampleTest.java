package ru.ussgroup.security.trusty;

import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Arrays;

import javax.security.auth.x500.X500PrivateCredential;

import org.junit.Before;
import org.junit.Test;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.ocsp.TrustyCachedOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.kalkan.KalkanOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyKeyStoreRepository;
import ru.ussgroup.security.trusty.repository.TrustyRepository;
import ru.ussgroup.security.trusty.utils.SignedData;

public class SyncVerifySignatureExampleTest {
    private TrustySignatureVerifier signatureVerifier;
    
    @Before
    public void init() throws UnknownHostException {
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyCertPathValidator certPathValidator = new TrustyCertPathValidator(repository, KalkanProvider.PROVIDER_NAME);
        
        TrustyOCSPValidator kalkanOCSPValidator = new KalkanOCSPValidator("http://1.1.1.1", "178.89.4.149", repository);
        
        TrustyOCSPValidator cachedOCSPValidator = new TrustyCachedOCSPValidator(kalkanOCSPValidator, 5, 60);
        
        TrustyCertificateValidator certificateValidator = new TrustyCertificateValidator(certPathValidator, cachedOCSPValidator);
        
        signatureVerifier = new TrustySignatureVerifier(certificateValidator);
    }
    
    @Test(expected = TrustyOCSPNotAvailableException.class)
    public void shouldSyncVerifySignature() throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException {
        X500PrivateCredential cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature;
        try {
            signature = TrustyUtils.sign(data, cert.getPrivateKey());
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        
        signatureVerifier.verify(Arrays.asList(new SignedData(data, signature, cert.getCertificate()),
                                               new SignedData("qwe".getBytes(StandardCharsets.UTF_8), signature, cert.getCertificate())));
    }
}

