package ru.ussgroup.security.trusty;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.x500.X500PrivateCredential;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

/*
 * getExtendedKeyUsage

1.3.6.1.5.5.7.3.2 - проверка подлинности клиента
1.2.398.5.19.1.2.2.1 - казначейство клиент или нотариат (необходимо исключить использование данных сертификатов)
1.2.398.6.1.1.1.1 - нотариат (необходимо исключить использование данных сертификатов)
*1.2.398.3.3.4.1.1 - физическое лицо
*1.2.398.3.3.4.1.2 - юридическое лицо
*1.2.398.3.3.4.1.2.1 – Первый руководитель
*1.2.398.3.3.4.1.2.2 – Лицо, наделенное правом подписи
*1.2.398.3.3.4.1.2.3 - Лицо, наделенное правом подписи финансовых документов
*1.2.398.3.3.4.1.2.5 – Сотрудник организации

* - только в новых сертификатах

Новые сертификаты с новым OID:
Политики действия сертификатов (одинаковая для старых и для новых сертификатов):

1.2.398.3.3.1.1 Регламент Национального удостоверяющего центра Республики Казахстан
1.2.398.3.3.2.1 Политика применения регистрационных свидетельств электронной цифровой подписи юридических лиц Республики Казахстан
1.2.398.3.3.2.2 Политика применения регистрационных свидетельств аутентификации юридических лиц Республики Казахстан
1.2.398.3.3.2.3 Политика применения регистрационных свидетельств электронной цифровой подписи физических лиц Республики Казахстан
1.2.398.3.3.2.4 Политика применения регистрационных свидетельств аутентификации физических лиц Республики Казахстан
*/
public class TrustyUtils {
    static {
        boolean exists = false;
    
        for (Provider p : Security.getProviders()) {
            if (p.getName().equals(KalkanProvider.PROVIDER_NAME)) {
                exists = true;
            }
        }
    
        if (!exists) {
            Security.addProvider(new KalkanProvider());
        }
    }
    
    public static void verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws SignatureException, CertPathValidatorException, CertificateException {
        try {
            Signature s = Signature.getInstance(publicKey.getAlgorithm());
            
            s.initVerify(publicKey);
            s.update(data);
            
            if (!s.verify(signature)) {
                throw new SignatureException("Signature is not valid");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws SignatureException {
        try {
            Signature signature = Signature.getInstance(privateKey.getAlgorithm());
            
            signature.initSign(privateKey);
            signature.update(data);
            
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X509Certificate loadCertFromResources(String path) {
        try (InputStream in = TrustyUtils.class.getResourceAsStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X509Certificate loadCertFromFile(String path) {
        try (InputStream in = new FileInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X500PrivateCredential loadCredentialFromResources(String path, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            
            try (InputStream in = TrustyUtils.class.getResourceAsStream(path)) {
                return loadCredentialFromStream(password, keyStore, in);
            } 
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X500PrivateCredential loadCredentialFromFile(String path, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            
            try (InputStream in = new FileInputStream(path)) {
                return loadCredentialFromStream(password, keyStore, in);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static X500PrivateCredential loadCredentialFromStream(String password, KeyStore keyStore, InputStream in) {
        try {
            keyStore.load(in, password.toCharArray());
            
            Enumeration<String> aliases = keyStore.aliases();
            
            while (aliases.hasMoreElements()){
                String alias = aliases.nextElement();
                
                return new X500PrivateCredential((X509Certificate)keyStore.getCertificate(alias), 
                                                      (PrivateKey)keyStore.getKey(alias, password.toCharArray()));
            }
            
            return null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
