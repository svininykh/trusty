package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

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
        
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyOCSPValidator validator = new TrustyCachedOCSPValidator(new KalkanOCSPValidator("http://ocsp.pki.gov.kz/ocsp/", repository), 5, 60);
        
        TrustyOCSPValidationResult result = validator.validate(oldGostCert, oldRsaCert, oldRsaExpiredCert, oldRsaRevokedCert)
                                                     .get();

        Assert.assertEquals(TrustyOCSPStatusInfo.GOOD,    result.getStatuses().get(oldGostCert.getSerialNumber()).getState());
        Assert.assertEquals(TrustyOCSPStatusInfo.GOOD,    result.getStatuses().get(oldRsaCert.getSerialNumber()).getState());
        Assert.assertEquals(TrustyOCSPStatusInfo.GOOD,    result.getStatuses().get(oldRsaExpiredCert.getSerialNumber()).getState());
        Assert.assertEquals(TrustyOCSPStatusInfo.REVOKED, result.getStatuses().get(oldRsaRevokedCert.getSerialNumber()).getState());
    }
}
