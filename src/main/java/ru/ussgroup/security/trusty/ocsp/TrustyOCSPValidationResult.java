package ru.ussgroup.security.trusty.ocsp;

import java.math.BigInteger;
import java.util.Map;

public class TrustyOCSPValidationResult {
    private Object response;
    
    private Map<BigInteger, TrustyOCSPStatusInfo> statuses;

    public TrustyOCSPValidationResult(Object response, Map<BigInteger, TrustyOCSPStatusInfo> statuses) {
        this.response = response;
        this.statuses = statuses;
    }

    public Object getResponse() {
        return response;
    }

    public Map<BigInteger, TrustyOCSPStatusInfo> getStatuses() {
        return statuses;
    }
}
