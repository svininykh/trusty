package ru.ussgroup.security.trusty;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.jce.X509Principal;

public class TrustySubjectDNParser {
    private Map<String, String> names = new HashMap<>();
    
    public TrustySubjectDNParser(Principal principal) {
        if (principal instanceof X509Principal) {
            X509Principal p = (X509Principal) principal;
            
            @SuppressWarnings("unchecked")
            Enumeration<DERSet> enumeration = ((DERSequence) p.getDERObject()).getObjects();
            
            while (enumeration.hasMoreElements()) {
                DERSet ds = enumeration.nextElement();
                
                DERSequence seq = (DERSequence) ds.getObjectAt(0);
                
                String key = seq.getObjectAt(0).toString();
                String value = seq.getObjectAt(1).toString();
                
                if (key.equals(X509Principal.SERIALNUMBER.getId())) {
                    names.put(X509Principal.SERIALNUMBER.getId(), value);
                }
                
                if (key.equals(X509Principal.OU.getId())) {
                    names.put(X509Principal.OU.getId(), value);
                }
                
                if (key.equals(X509Principal.CN.getId())) {
                    names.put(X509Principal.CN.getId(), value);
                }
                
                if (key.equals(X509Principal.EmailAddress.getId())) {
                    names.put(X509Principal.EmailAddress.getId(), value);
                }
            }
        } else {
            String[] values = principal.getName().split(",");
            
            names = new HashMap<>();
            
            for (String value : values) {
                names.put(value.split("=")[0].trim(), value.split("=")[1].trim());
            }
        }
    }
    
    public String getIin() {
        return names.get(X509Principal.SERIALNUMBER.getId()).substring(3);
    }
    
    public String getBin() {
        return names.get(X509Principal.OU.getId()).substring(3);
    }
    
    public String getCommonName() {
        return names.get(X509Principal.CN.getId()).substring(3);
    }
    
    public String getEmail() {
        return names.get(X509Principal.EmailAddress.getId());
    }
}
