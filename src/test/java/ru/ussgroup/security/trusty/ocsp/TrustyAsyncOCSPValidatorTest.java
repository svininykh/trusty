package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

import com.google.common.collect.ImmutableSet;

import ru.ussgroup.security.trusty.TrustyUtils;
import ru.ussgroup.security.trusty.ocsp.kalkan.KalkanOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyKeyStoreRepository;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

public class TrustyAsyncOCSPValidatorTest {
    @Test
    public void shouldValidate() throws Exception {
        X509Certificate oldGostCert       = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456").getCertificate();
        X509Certificate oldRsaCert        = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0.p12",  "123456").getCertificate();
        X509Certificate oldRsaExpiredCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0_expired.p12",  "123456").getCertificate();
        X509Certificate oldRsaRevokedCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0_revoked.p12",  "123456").getCertificate();
        X509Certificate newRsaCert        = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_2.0.p12", "123456").getCertificate();
        X509Certificate newGostCert       = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456").getCertificate();
        
        X509Certificate kucGOST           = TrustyUtils.loadCertFromResources("/ca/kuc_gost_1.0.crt");
        X509Certificate kucRSA            = TrustyUtils.loadCertFromResources("/ca/kuc_rsa_1.0.crt");
        
        X509Certificate nucGOST2           = TrustyUtils.loadCertFromResources("/ca/nuc_gost_2.0.crt");
        X509Certificate nucRSA2            = TrustyUtils.loadCertFromResources("/ca/nuc_rsa_2.0.crt");
        
        X509Certificate nucGOST1           = TrustyUtils.loadCertFromResources("/ca/nuc_gost_1.0.cer");
        X509Certificate nucRSA1            = TrustyUtils.loadCertFromResources("/ca/nuc_rsa_1.0.cer");
        
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyOCSPValidator validator = new TrustyCachedOCSPValidator(new KalkanOCSPValidator("http://ocsp.pki.gov.kz/", "178.89.4.149", repository), 5, 60);
        
        TrustyOCSPValidationResult result = validator.validateAsync(ImmutableSet.of(kucGOST, kucRSA, nucGOST2, nucRSA2, nucGOST1, nucRSA1)).get();
        
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(nucGOST1.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(nucRSA1.getSerialNumber()).getStatus());
//        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(kucGOST.getSerialNumber()).getStatus());
//        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(kucRSA.getSerialNumber()).getStatus());
//        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(nucGOST2.getSerialNumber()).getStatus());
//        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(nucRSA2.getSerialNumber()).getStatus());
        
        X509Certificate privAuth = TrustyUtils.loadCredentialFromFile("c:/1/testcerts/new_priv_auth.p12", "123456").getCertificate();
        X509Certificate privRsa  = TrustyUtils.loadCredentialFromFile("c:/1/testcerts/new_priv_rsa.p12",  "123456").getCertificate();
        X509Certificate urAuth = TrustyUtils.loadCredentialFromFile("c:/1/testcerts/new_ur_auth.p12", "123456").getCertificate();
        X509Certificate urGost  = TrustyUtils.loadCredentialFromFile("c:/1/testcerts/new_ur_gost.p12",  "123456").getCertificate();
        
        result = validator.validateAsync(ImmutableSet.of(privAuth, privRsa, urAuth, urGost)).get();
        
        Assert.assertEquals(TrustyOCSPStatus.GOOD, result.getStatuses().get(privAuth.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD, result.getStatuses().get(privRsa.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD, result.getStatuses().get(urAuth.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD, result.getStatuses().get(urGost.getSerialNumber()).getStatus());
    }
}
