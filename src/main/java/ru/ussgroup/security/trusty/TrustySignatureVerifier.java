package ru.ussgroup.security.trusty;

import java.math.BigInteger;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ru.ussgroup.security.trusty.utils.SignedData;

public class TrustySignatureVerifier {
    private TrustyCertificateValidator certificateValidator;

    public TrustySignatureVerifier(TrustyCertificateValidator certificateValidator) {
        this.certificateValidator = certificateValidator;
    }
    
    public List<SignedData> verify(List<SignedData> list) {
        Set<X509Certificate> certs = list.stream().map(SignedData::getCert).collect(Collectors.toSet());
        
        CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> future = certificateValidator.validate(certs);
        
        List<SignedData> verifiedList = list.parallelStream().map(sd -> {
            try {
                Signature s = Signature.getInstance(sd.getCert().getPublicKey().getAlgorithm());
                
                s.initVerify(sd.getCert().getPublicKey());
                s.update(sd.getData());
                
                if (!s.verify(sd.getSignature())) {
                    throw new SignatureException();
                }
            } catch (Exception e) {
                sd.setValid(false);
            }
            
            return sd;
        }).collect(Collectors.toList());
        
        Map<BigInteger, TrustyCertValidationCode> certsResults;
        
        try {
            certsResults = future.get();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        for (SignedData sd : verifiedList) {
            TrustyCertValidationCode code = certsResults.get(sd.getCert().getSerialNumber());
            
            if (code != TrustyCertValidationCode.SUCCESS) {
                sd.setValid(false);
                sd.setCertStatus(code);
            }
        }
        
        return verifiedList;
    }
}
