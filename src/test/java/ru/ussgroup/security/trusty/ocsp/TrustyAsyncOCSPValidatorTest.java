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
        X509Certificate kucGost           = TrustyUtils.loadCertFromResources("/ca/kuc_gost_1.0.crt");
        X509Certificate nucGost2          = TrustyUtils.loadCertFromResources("/ca/nuc_gost_2.0.crt");
        
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyOCSPValidator validator = new TrustyCachedOCSPValidator(new KalkanOCSPValidator("http://ocsp.pki.gov.kz/ocsp/", repository), 5, 60);
        
        TrustyOCSPValidationResult result = validator.validateAsync(ImmutableSet.of(oldGostCert, oldRsaCert, oldRsaExpiredCert, oldRsaRevokedCert, newRsaCert, kucGost, nucGost2)).get();

        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(oldGostCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(oldRsaCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(oldRsaExpiredCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.REVOKED, result.getStatuses().get(oldRsaRevokedCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(newRsaCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(kucGost.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(nucGost2.getSerialNumber()).getStatus());
    }
}
