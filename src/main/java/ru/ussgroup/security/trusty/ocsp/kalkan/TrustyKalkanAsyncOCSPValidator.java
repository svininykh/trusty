package ru.ussgroup.security.trusty.ocsp.kalkan;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Hashtable;

import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.Response;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.ocsp.CertificateID;
import kz.gov.pki.kalkan.ocsp.OCSPException;
import kz.gov.pki.kalkan.ocsp.OCSPReqGenerator;
import kz.gov.pki.kalkan.ocsp.OCSPResp;
import kz.gov.pki.kalkan.ocsp.RevokedStatus;
import kz.gov.pki.kalkan.ocsp.SingleResp;
import ru.ussgroup.security.trusty.KeyStoreTrustyRepository;
import ru.ussgroup.security.trusty.TrustyCertificateValidator;
import ru.ussgroup.security.trusty.TrustyRepository;
import ru.ussgroup.security.trusty.ocsp.DnsResolver;
import ru.ussgroup.security.trusty.ocsp.OCSPNonceException;
import ru.ussgroup.security.trusty.ocsp.OCSPNotAvailableException;
import ru.ussgroup.security.trusty.ocsp.OCSPStatusInfo;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;

public class TrustyKalkanAsyncOCSPValidator implements TrustyOCSPValidator {
    private final String ocspUrl;
    
    private final static AsyncHttpClient httpClient;
    
    private SecureRandom sr = new SecureRandom();
    
    private TrustyRepository trustyRepository;
    
    private TrustyCertificateValidator validator;
    
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
    
    public TrustyKalkanAsyncOCSPValidator(String ocspUrl) {
        this(ocspUrl, new KeyStoreTrustyRepository());
    }

    public TrustyKalkanAsyncOCSPValidator(String ocspUrl, TrustyRepository trustyRepository) {
        this.ocspUrl = ocspUrl;
        this.trustyRepository = trustyRepository;
        validator = new TrustyCertificateValidator(this);
        DnsResolver.addDomainName(ocspUrl);
    }
    
    public OCSPStatusInfo validate(X509Certificate cert) throws OCSPNotAvailableException {
        try {
            byte[] nonce = new byte[4];
            sr.nextBytes(nonce);
            
            Response r = httpClient.preparePost(ocspUrl)
                                   .setHeader("Content-Type", "application/ocsp-request")
                                   .setInetAddress(DnsResolver.getInetAddress(ocspUrl))
                                   .setBody(getOcspPackage(cert, nonce))
                                   .execute()
                                   .get();
            
            OCSPResp response = new OCSPResp(r.getResponseBodyAsBytes());
            
            if (response.getStatus() != 0) {
                throw new OCSPException("Unsuccessful request. Status: " + response.getStatus());
            }
            
            BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
            
            byte[] respNonceExt = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
            
            if (respNonceExt != null) {
                try (ASN1InputStream asn1In1 = new ASN1InputStream(respNonceExt)) {
                    DERObject derObj = asn1In1.readObject();
                    
                    byte[] extV = DEROctetString.getInstance(derObj).getOctets();
                    
                    try(ASN1InputStream asn1In2 = new ASN1InputStream(extV)) {
                        derObj = asn1In2.readObject();
                        byte[] receivedNonce = DEROctetString.getInstance(derObj).getOctets();
                        if (!java.util.Arrays.equals(nonce, receivedNonce)) {
                            throw new OCSPNonceException("Expected nonce: " + Base64.getEncoder().encode(nonce) + ", but received: " + Base64.getEncoder().encode(receivedNonce));
                        }
                    }
                }
            } else {
                throw new OCSPNonceException("Nonce extension not found in response!");
            }
            
            X509Certificate ocspcert = brep.getCerts(KalkanProvider.PROVIDER_NAME)[0];
            
//            validator.validate(ocspcert);ошибка валидации: провайдер не поддерживает критическое расширение
            
            if (!brep.verify(ocspcert.getPublicKey(), KalkanProvider.PROVIDER_NAME)) {
                throw new OCSPException("Unable to verify response");
            }
            
            SingleResp singleResp = brep.getResponses()[0]; 

            Object status = singleResp.getCertStatus();

            if (status == null) {
                return new OCSPStatusInfo(OCSPStatusInfo.GOOD);
            } else if (status instanceof RevokedStatus) {
                int reason = 0;

                if (((RevokedStatus) status).hasRevocationReason()) {
                    reason = ((RevokedStatus) status).getRevocationReason();
                }

                return new OCSPStatusInfo(OCSPStatusInfo.REVOKED, ((RevokedStatus) status).getRevocationTime(), reason);
            }
            
            return new OCSPStatusInfo(OCSPStatusInfo.UNKNOWN);
        } catch (Exception e) {
            throw new OCSPNotAvailableException(e);
        }
    }
    
    private byte[] getOcspPackage(X509Certificate cert, byte[] nonce) throws Exception {
        OCSPReqGenerator gen = new OCSPReqGenerator();
        
        CertificateID certId = new CertificateID(CertificateID.HASH_GOST34311GT, trustyRepository.getIssuer(cert), cert.getSerialNumber(), KalkanProvider.PROVIDER_NAME);
        
        gen.addRequest(certId);
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
}
