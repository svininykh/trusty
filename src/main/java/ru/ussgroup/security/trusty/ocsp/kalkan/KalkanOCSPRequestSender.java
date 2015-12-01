package ru.ussgroup.security.trusty.ocsp.kalkan;

import java.io.IOException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.Response;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.CertificateID;
import kz.gov.pki.kalkan.ocsp.OCSPException;
import kz.gov.pki.kalkan.ocsp.OCSPReqGenerator;
import kz.gov.pki.kalkan.ocsp.OCSPResp;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.repository.TrustyRepository;
import ru.ussgroup.security.trusty.utils.DnsResolver;

/**
 * This class is thread-safe
 */
public class KalkanOCSPRequestSender {
    private final String ocspUrl;
    
    private final TrustyRepository trustyRepository;
    
    private final static AsyncHttpClient httpClient;
    
    private final SecureRandom sr = new SecureRandom();
    
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
    
    static {
        AsyncHttpClientConfig cfg = new AsyncHttpClientConfig.Builder().setConnectTimeout(10_000)
                                                                       .setRequestTimeout(10_000)
                                                                       .build();
        httpClient = new AsyncHttpClient(cfg);
        
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                httpClient.close();
            }
        });
    }
    
    public KalkanOCSPRequestSender(String ocspUrl, TrustyRepository trustyRepository) {
        this.ocspUrl = ocspUrl;
        this.trustyRepository = trustyRepository;
        DnsResolver.addDomainName(ocspUrl);
    }
    
    public KalkanOCSPResponse sendRequest(Set<X509Certificate> certs) {
        try {
            byte[] nonce = new byte[4];
            sr.nextBytes(nonce);
            
            List<CertificateID> ids = new ArrayList<>();
            
            for (X509Certificate cert : certs) {
                ids.add(new CertificateID(CertificateID.HASH_GOST34311GT, trustyRepository.getIssuer(cert), cert.getSerialNumber(), KalkanProvider.PROVIDER_NAME));
            }
            
            ListenableFuture<OCSPResp> f = httpClient.preparePost(ocspUrl)
                                                     .setHeader("Content-Type", "application/ocsp-request")
                                                     .setInetAddress(DnsResolver.getInetAddress(ocspUrl))
                                                     .setBody(getOcspPackage(ids, nonce))
                                                     .execute(new AsyncCompletionHandler<OCSPResp>() {
                                                         @Override
                                                         public OCSPResp onCompleted(Response response) throws Exception {
                                                             return new OCSPResp(response.getResponseBodyAsBytes());
                                                         }
                                                     });
            
            CompletableFuture<OCSPResp> completableFuture = new CompletableFuture<>();
            
            f.addListener(() -> {
                try {
                    completableFuture.complete(f.get());
                } catch (InterruptedException | ExecutionException e) {//Сделал двойную вложенность, для унификации обработки в синхронных методах
                    completableFuture.completeExceptionally(new RuntimeException(new TrustyOCSPNotAvailableException(e)));
                }
            }, r -> {r.run();});
            
            return new KalkanOCSPResponse(nonce, completableFuture);
        } catch (OCSPException | IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    private byte[] getOcspPackage(List<CertificateID> ids, byte[] nonce) throws OCSPException, IOException {
        OCSPReqGenerator gen = new OCSPReqGenerator();
        
        for (CertificateID id : ids) {
            gen.addRequest(id);
        }
        
        gen.setRequestExtensions(generateExtensions(nonce));
        
        return gen.generate().getEncoded();
    }
    
    private X509Extensions generateExtensions(byte[] nonce) {
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<>();
        
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, new X509Extension(false, new DEROctetString(new DEROctetString(nonce))));

        ASN1EncodableVector prefSigAlgV = new ASN1EncodableVector();
//      prefSigAlgV.add(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411_94_with_gostR34310_2004));
        prefSigAlgV.add(new AlgorithmIdentifier(KNCAObjectIdentifiers.gost34311_95_with_gost34310_2004));
        ASN1EncodableVector prefSigAlgsV = new ASN1EncodableVector();
        prefSigAlgsV.add(new DERSequence(prefSigAlgV));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_pref_sig_algs, new X509Extension(false, new DEROctetString(new DERSequence(prefSigAlgsV))));
        
        return new X509Extensions(exts);
    }
    
    public TrustyRepository getRepository() {
        return trustyRepository;
    }
}
