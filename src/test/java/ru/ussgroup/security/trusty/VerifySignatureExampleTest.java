package ru.ussgroup.security.trusty;

import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500PrivateCredential;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import ru.ussgroup.security.trusty.ocsp.TrustyCachedOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.kalkan.KalkanOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyKeyStoreRepository;
import ru.ussgroup.security.trusty.repository.TrustyRepository;
import ru.ussgroup.security.trusty.utils.SignedData;

public class VerifySignatureExampleTest {
    private TrustySignatureVerifier signatureVerifier;
    
    @Before
    public void init() {
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyCertPathValidator certPathValidator = new TrustyCertPathValidator.Builder(repository).setProvider(KalkanProvider.PROVIDER_NAME).build();
        
        TrustyOCSPValidator kalkanOCSPValidator = new KalkanOCSPValidator("http://ocsp.pki.gov.kz/ocsp/", repository);
        
        TrustyOCSPValidator cachedOCSPValidator = new TrustyCachedOCSPValidator(kalkanOCSPValidator, 5, 60);
        
        TrustyCertificateValidator certificateValidator = new TrustyCertificateValidator(certPathValidator, cachedOCSPValidator);
        
        signatureVerifier = new TrustySignatureVerifier(certificateValidator);
    }
    
    @Test
    public void shouldVerifySignature() throws SignatureException, CertPathValidatorException, CertificateException {
        X500PrivateCredential cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = TrustyUtils.sign(data, cert.getPrivateKey());
        
        List<SignedData> results = signatureVerifier.verify(Arrays.asList(new SignedData(data, signature, cert.getCertificate()),
                                                                          new SignedData("qwe".getBytes(StandardCharsets.UTF_8), signature, cert.getCertificate())));
        
        Assert.assertTrue(results.get(0).isValid());
        Assert.assertFalse(results.get(1).isValid());
    }
}
