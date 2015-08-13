package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

import ru.ussgroup.security.trusty.ocsp.OCSPStatusInfo;
import ru.ussgroup.security.trusty.ocsp.TrustyCachedOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.kalkan.KalkanOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyKeyStoreRepository;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

public class TrustyAsyncOCSPValidatorTest {
    @Test
    public void shouldValidate() throws Exception {
        X509Certificate oldGostCert       = TrustyUtils.loadKeyFromResources("/example/ul_gost_1.0.p12", "123456");
        X509Certificate newGostCert       = TrustyUtils.loadKeyFromResources("/example/ul_gost_2.0.p12", "123456");
        X509Certificate oldRsaCert        = TrustyUtils.loadKeyFromResources("/example/ul_rsa_1.0.p12",  "123456");
        X509Certificate newRsaCert        = TrustyUtils.loadKeyFromResources("/example/ul_rsa_2.0.p12",  "123456");
        X509Certificate oldRsaExpiredCert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_1.0_expired.p12",  "123456");
        X509Certificate oldRsaRevokedCert = TrustyUtils.loadKeyFromResources("/example/ul_rsa_1.0_revoked.p12",  "123456");
        
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyOCSPValidator validator = new KalkanOCSPValidator("http://beren.pki.kz/ocsp/", repository);
        
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(oldGostCert).getState());
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(newGostCert).getState());
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(oldRsaCert).getState());
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(newRsaCert).getState());
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(oldRsaExpiredCert).getState());
        Assert.assertEquals(OCSPStatusInfo.REVOKED, validator.validate(oldRsaRevokedCert).getState());
        
        validator = new TrustyCachedOCSPValidator(validator, 5, 60);
        
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(oldGostCert).getState());
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(newGostCert).getState());
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(oldRsaCert).getState());
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(newRsaCert).getState());
        Assert.assertEquals(OCSPStatusInfo.GOOD,    validator.validate(oldRsaExpiredCert).getState());
        Assert.assertEquals(OCSPStatusInfo.REVOKED, validator.validate(oldRsaRevokedCert).getState());
    }
}
