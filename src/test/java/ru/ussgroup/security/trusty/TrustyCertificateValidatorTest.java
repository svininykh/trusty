package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Assert;
import org.junit.Test;

import kz.gov.pki.kalkan.jce.exception.ExtCertPathValidatorException;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.kalkan.TrustyKalkanAsyncOCSPValidator;

public class TrustyCertificateValidatorTest {
    @Test
    public void shouldValidateCertificates() throws Exception {
        TrustyOCSPValidator ocspValidator = new TrustyKalkanAsyncOCSPValidator("http://beren.pki.kz/ocsp/");
        
        TrustyCertificateValidator validator = new TrustyCertificateValidator(ocspValidator);
        
        X509Certificate oldGostCert = TrustyUtils.loadKeyFromResources("/example/ul_gost_1.0.p12", "123456");
        X509Certificate newGostCert = TrustyUtils.loadKeyFromResources("/example/ul_gost_2.0.p12", "123456");
        X509Certificate oldRsaCert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_1.0.p12", "123456");
        X509Certificate newRsaCert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_2.0.p12", "123456");
        
        validator.validate(oldGostCert);
        validator.validate(newGostCert);
        validator.validate(oldRsaCert);
        validator.validate(newRsaCert);
    }
    
    @Test(expected = ExtCertPathValidatorException.class)
    public void shouldThrowExceptionIfExpired() throws Exception {
        TrustyKalkanAsyncOCSPValidator ocspValidator = new TrustyKalkanAsyncOCSPValidator("http://beren.pki.kz/ocsp/");
        
        TrustyCertificateValidator validator = new TrustyCertificateValidator(ocspValidator);
        
        X509Certificate oldExpiredRsaCert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_1.0_expired.p12", "123456");
        
        validator.validate(oldExpiredRsaCert);
    }
    
    @Test
    public void shouldParallelValidateOldGostCert() throws Exception {
        X509Certificate cert = TrustyUtils.loadKeyFromResources("/example/ul_gost_1.0.p12", "123456");
        
        shouldParallelValidateOldCertificates(cert);
    }
    
    @Test
    public void shouldParallelValidateOldRsaCert() throws Exception {
        X509Certificate cert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_1.0.p12", "123456");
        
        shouldParallelValidateOldCertificates(cert);
    }
    
    @Test
    public void shouldParallelValidateNewGostCert() throws Exception {
        X509Certificate cert = TrustyUtils.loadKeyFromResources("/example/ul_gost_2.0.p12", "123456");
        
        shouldParallelValidateOldCertificates(cert);
    }
    
    @Test
    public void shouldParallelValidateNewRsaCert() throws Exception {
        X509Certificate cert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_2.0.p12", "123456");
        
        shouldParallelValidateOldCertificates(cert);
    }
    
    public void shouldParallelValidateOldCertificates(X509Certificate cert) throws Exception {
        List<Thread> threads = new ArrayList<>();
        
        final AtomicBoolean successful = new AtomicBoolean(true);
        
        for (int i = 0; i < 1_00; i++) {
            Thread t = new Thread() {
                @Override
                public void run() {
                    try {
                        TrustyKalkanAsyncOCSPValidator ocspValidator = new TrustyKalkanAsyncOCSPValidator("http://beren.pki.kz/ocsp/");
                        
                        TrustyCertificateValidator validator = new TrustyCertificateValidator(ocspValidator);
                        
                        for (int i = 0; i < 1_000; i++) {
                            validator.validate(cert);
                        }
                    } catch (Exception e) {
                        successful.set(false);
                        e.printStackTrace();
                    }
                }
            };

            t.start();
            threads.add(t);
        }
        
        for (Thread t : threads) {
            t.join();
        }
        
        Assert.assertTrue("At least one thread execution failed", successful.get());
    }
}
