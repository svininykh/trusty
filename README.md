### T-R-U-S-T-Y (Only for Java 8)

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
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.security.auth.x500.X500PrivateCredential;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import ru.ussgroup.security.trusty.exception.TrustyOCSPCertPathValidatorException;
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

public class VerifySignatureExampleTest {
    private TrustySignatureVerifier signatureVerifier;
    
    @Before
    public void init() {
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyCertPathValidator certPathValidator = new TrustyCertPathValidator(repository, KalkanProvider.PROVIDER_NAME);
        
        TrustyOCSPValidator kalkanOCSPValidator = new KalkanOCSPValidator("http://ocsp.pki.gov.kz/ocsp/", repository);
        
        TrustyOCSPValidator cachedOCSPValidator = new TrustyCachedOCSPValidator(kalkanOCSPValidator, 5, 60);
        
        TrustyCertificateValidator certificateValidator = new TrustyCertificateValidator(certPathValidator, cachedOCSPValidator);
        
        signatureVerifier = new TrustySignatureVerifier(certificateValidator);
    }
    
    @Test
    public void shouldVerifySignature() throws InterruptedException, ExecutionException {
        X500PrivateCredential cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature;
        try {
            signature = TrustyUtils.sign(data, cert.getPrivateKey());
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        
        List<SignedData> results = signatureVerifier.verifyAsync(Arrays.asList(new SignedData(data, signature, cert.getCertificate()),
                                                                               new SignedData("qwe".getBytes(StandardCharsets.UTF_8), signature, cert.getCertificate()))).get();
        
        Assert.assertTrue(results.get(0).isValid());
        Assert.assertFalse(results.get(1).isValid());
    }
    
    @Test
    public void shouldSyncVerifySignature() throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPCertPathValidatorException, TrustyOCSPUnknownProblemException {
        X500PrivateCredential cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature;
        try {
            signature = TrustyUtils.sign(data, cert.getPrivateKey());
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        
        List<SignedData> results = signatureVerifier.verify(Arrays.asList(new SignedData(data, signature, cert.getCertificate()),
                                                                          new SignedData("qwe".getBytes(StandardCharsets.UTF_8), signature, cert.getCertificate())));
        
        Assert.assertTrue(results.get(0).isValid());
        Assert.assertFalse(results.get(1).isValid());
    }
}

```
####Подключение через Maven:

Необходимо добавить в pom.xml строки:
```xml
  <dependencies>
    <dependency>
      <groupId>ru.uss-group.security</groupId>
      <artifactId>trusty</artifactId>
      <version>0.0.1-SNAPSHOT</version>
    </dependency>
  </dependencies>
  
  <repositories>
    <repository>
        <id>ru.uss-group</id>
        <url>https://raw.githubusercontent.com/man4j/trusty/master/maven</url>
    </repository>
  </repositories>
  
  ```

####Обратная связь: 

man4j@ya.ru
