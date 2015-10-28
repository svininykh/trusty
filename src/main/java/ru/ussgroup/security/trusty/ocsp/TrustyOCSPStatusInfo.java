package ru.ussgroup.security.trusty.ocsp;

import java.util.Date;

public class TrustyOCSPStatusInfo {
    public static final int GOOD = 1;
    public static final int REVOKED = 2;
    public static final int UNKNOWN = 3;

    private int state;

    private Date revocationTime;

    private int revocationReason;
    
    public TrustyOCSPStatusInfo(int state, Date revocationTime, int revocationReason) {
        this.state = state;
        this.revocationTime = revocationTime;
        this.revocationReason = revocationReason;
    }

    public TrustyOCSPStatusInfo(int state) {
        this.state = state;
    }

    public int getState() {
        return state;
    }

    public Date getRevocationTime() {
        return revocationTime;
    }

    public int getRevocationReason() {
        return revocationReason;
    }
}
