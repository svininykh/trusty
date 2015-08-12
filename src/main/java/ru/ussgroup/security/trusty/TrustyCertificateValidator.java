package ru.ussgroup.security.trusty;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import ru.ussgroup.security.trusty.ocsp.OCSPNotAvailableException;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;

public class TrustyCertificateValidator {
    private PKIXBuilderParameters params;
    
    private TrustyRepository trustyRepository;
    
    private CertPathValidator certPathValidator;
    
    private CertificateFactory certificateFactory;
    
    public TrustyCertificateValidator(TrustyOCSPValidator ocspValidator) {
        this(ocspValidator, new KeyStoreTrustyRepository());
    }

    public TrustyCertificateValidator(TrustyOCSPValidator ocspValidator, TrustyRepository trustyRepository) {
        try {
            this.trustyRepository = trustyRepository;
            certPathValidator = CertPathValidator.getInstance("PKIX");
            certificateFactory = CertificateFactory.getInstance("X.509");
            params = new PKIXBuilderParameters(trustyRepository.getTrustedCerts().stream().map(c -> new TrustAnchor(c, null)).collect(Collectors.toSet()), null);
            params.setRevocationEnabled(false);
            params.addCertPathChecker(new PKIXCertPathChecker() {
                @Override
                public boolean isForwardCheckingSupported() {return false;}
                
                @Override
                public void init(boolean forward) throws CertPathValidatorException {}
                
                @Override
                public Set<String> getSupportedExtensions() {return null;}
                
                @Override
                public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
                    try {
                        ocspValidator.validate((X509Certificate) cert);
                    } catch (OCSPNotAvailableException e) {
                        throw new CertPathValidatorException(e);
                    }
                }
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public void validate(X509Certificate cert) throws CertPathValidatorException, InvalidAlgorithmParameterException, CertificateException {
        List<Certificate> list = new ArrayList<>();
        
        list.add(cert);
        
        X509Certificate current = cert;
        
        while (true) {        
            X509Certificate x509IntermediateCert = trustyRepository.getIntermediateCert(current);
            
            if (x509IntermediateCert != null) {
                list.add(x509IntermediateCert);
                
                current = x509IntermediateCert;
            } else {
                break;
            }
        }
        
        certPathValidator.validate(certificateFactory.generateCertPath(list), params);
    }
}
