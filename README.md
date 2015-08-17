### T-R-U-S-T-Y

####Возможности:

1. Поддержка сертификатов НУЦ v1.0 и НУЦ v2.0.
2. Проверка ЭЦП согласно рекомендациям НУЦ.
3. Высокопроизводительный OCSP валидатор с функцией кеширования.
4. Дополнительные проверки параметров сертификата.

####Порядок проверки сертификата:
1. Построение цепочки доверия от сертификата пользователя до корневого сертификата НУЦ v1.0 или КУЦ.
2. Проверка срока действия сертификатов в цепочке доверия.
3. Проверка ЭЦП сертификатов в цепочке доверия.
4. Проверка на отозванность сертификатов в цепочке доверия.
5. Проверка является ли сертификат подходящим для авторизации или подписи (необязательно).
6. Проверка ИИН и БИН входящие в сертификат (необязательно).
7. Проверка является ли сертификат персональным или сертификатом ЮЛ (необязательно).

####Пример кода:
```java
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
}

```
