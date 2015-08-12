package ru.ussgroup.security.trusty;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

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
    
    public static X509Certificate loadKeyFromResources(String path, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            
            try (InputStream in = TrustyUtils.class.getResourceAsStream(path)) {
                return loadKeyFromStream(password, keyStore, in);
            } 
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X509Certificate loadKeyFromFile(String path, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            
            try (InputStream in = new FileInputStream(path)) {
                return loadKeyFromStream(password, keyStore, in);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate loadKeyFromStream(String password, KeyStore keyStore, InputStream in) {
        try {
            keyStore.load(in, password.toCharArray());
            
            Enumeration<String> aliases = keyStore.aliases();
            
            while (aliases.hasMoreElements()){
                String alias = aliases.nextElement();
                for (Certificate c : keyStore.getCertificateChain(alias)) {
                    return (X509Certificate) c;
                }
            }
            
            return null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
