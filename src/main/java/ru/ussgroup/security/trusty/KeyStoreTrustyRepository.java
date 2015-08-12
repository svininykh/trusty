package ru.ussgroup.security.trusty;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.collect.ImmutableList;

public class KeyStoreTrustyRepository implements TrustyRepository {
    private static Map<String, X509Certificate> intermediateMap = new ConcurrentHashMap<>();
    private static Map<String, X509Certificate> trustedMap = new ConcurrentHashMap<>();

    static {
        try {
            KeyStore keyStore = KeyStore.getInstance("jks");
            
            try (InputStream in = KeyStoreTrustyRepository.class.getResourceAsStream("/ca/repository.jks")) {
                keyStore.load(in, "123456".toCharArray());
            }

            Enumeration<String> aliases = keyStore.aliases();
            
            while (aliases.hasMoreElements()) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(aliases.nextElement());
                
                if (Arrays.equals(cert.getSubjectX500Principal().getEncoded(),cert.getIssuerX500Principal().getEncoded())) {
                    trustedMap.put(cert.getSigAlgOID() + Base64.getEncoder().encodeToString(cert.getSubjectX500Principal().getEncoded()), cert);
                } else {
                    intermediateMap.put(cert.getSigAlgOID() + Base64.getEncoder().encodeToString(cert.getSubjectX500Principal().getEncoded()), cert);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Collection<X509Certificate> getTrustedCerts() {
        return ImmutableList.copyOf(trustedMap.values());
    }

    @Override
    public X509Certificate getIntermediateCert(X509Certificate cert) {
        return intermediateMap.get(cert.getSigAlgOID() + Base64.getEncoder().encodeToString(cert.getIssuerX500Principal().getEncoded()));
    }
    
    @Override
    public X509Certificate getIssuer(X509Certificate cert) {
        X509Certificate issuer = intermediateMap.get(cert.getSigAlgOID() + Base64.getEncoder().encodeToString(cert.getIssuerX500Principal().getEncoded()));
        
        if (issuer != null) return issuer; 
            
        return trustedMap.get(cert.getSigAlgOID() + Base64.getEncoder().encodeToString(cert.getIssuerX500Principal().getEncoded()));
    }
}
