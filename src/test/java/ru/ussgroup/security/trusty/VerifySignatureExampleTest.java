package ru.ussgroup.security.trusty;

import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500PrivateCredential;

import org.junit.Test;

import ru.ussgroup.security.trusty.ocsp.TrustyCachedOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.kalkan.KalkanOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyKeyStoreRepository;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

public class VerifySignatureExampleTest {
    @Test
    public void shouldVerifySignature() throws SignatureException, CertPathValidatorException, CertificateException {
        X500PrivateCredential newGostCert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = TrustyUtils.sign(data, newGostCert.getPrivateKey());
        
        verifySignature(data, signature, newGostCert.getCertificate());
    }
    
    @Test
    public void shouldVerifySignatureWithExpiredCert() throws SignatureException, CertPathValidatorException, CertificateException {
        X500PrivateCredential expiredRsaCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0_expired.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = TrustyUtils.sign(data, expiredRsaCert.getPrivateKey());
        
        verifySignatureWithExpiredCert(data, signature, expiredRsaCert.getCertificate());
    }
    
    private void verifySignature(byte[] data, byte[] signature, X509Certificate cert) throws SignatureException, CertPathValidatorException, CertificateException {
        TrustyUtils.verifySignature(data, signature, cert.getPublicKey());
        
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyOCSPValidator kalkanOCSPValidator = new KalkanOCSPValidator("http://beren.pki.kz/ocsp/", repository);
        
        TrustyCachedOCSPValidator cachedOCSPValidator = new TrustyCachedOCSPValidator(kalkanOCSPValidator, 5, 60);
        
        TrustyCertificateValidator validator = new TrustyCertificateValidator.Builder(cachedOCSPValidator).checkIsEnterprise()
                                                                                                          .checkForSigning()
                                                                                                          .build();
        
        validator.validate(cert);
    }
    
    private void verifySignatureWithExpiredCert(byte[] data, byte[] signature, X509Certificate cert) throws SignatureException, CertPathValidatorException, CertificateException {
        TrustyUtils.verifySignature(data, signature, cert.getPublicKey());
        
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyOCSPValidator kalkanOCSPValidator = new KalkanOCSPValidator("http://beren.pki.kz/ocsp/", repository);
        
        TrustyCachedOCSPValidator cachedOCSPValidator = new TrustyCachedOCSPValidator(kalkanOCSPValidator, 5, 60);
        
        TrustyCertificateValidator validator = new TrustyCertificateValidator.Builder(cachedOCSPValidator).setDate(cert.getNotBefore())
                                                                                                          .build();
        
        validator.validate(cert);
    }
}
