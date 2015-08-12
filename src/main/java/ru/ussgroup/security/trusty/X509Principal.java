package ru.ussgroup.security.trusty;

import java.security.Principal;
import java.util.Vector;

import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;

public class X509Principal extends kz.gov.pki.kalkan.jce.X509Principal {
    public X509Principal(Principal principal) {
        super((kz.gov.pki.kalkan.jce.X509Principal) principal);
        load();
    }

    /**
     * Load bean properties  from parent object
     */
    @SuppressWarnings("unchecked")
    private void load() {
        Vector<String> values = getValues();
        int i = 0;
        for (DERObjectIdentifier oid : (Vector<DERObjectIdentifier>) getOIDs()) {
            if (EmailAddress.equals(oid)) {
                email = values.elementAt(i);
            } else if (OU.equals(oid)) {
                tin = sanitize(values.elementAt(i));
            } else if (SERIALNUMBER.equals(oid)) {
                iin = sanitize(values.elementAt(i));
            } else if (CN.equals(oid)) {
                commonName = values.elementAt(i);
            }
            i++;
        }
    }

    /**
     * IIN
     */
    private String iin;

    /**
     * BIN / TIN
     */
    private String tin;

    /**
     * CN (Common Name)
     */
    private String commonName;

    /**
     * Email
     */
    private String email;

    public String getIin() {
        return iin;
    }

    public String getTin() {
        return tin;
    }

    public String getCommonName() {
        return commonName;
    }

    public String getEmail() {
        return email;
    }

    private String sanitize(String value) {
        if(value == null) {
            return value;
        }

        if(value.startsWith("BIN") || value.startsWith("IIN")) {
            return value.substring(3);
        }

        return value;
    }
}
