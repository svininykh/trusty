package ru.ussgroup.security.trusty.exception;

public class TrustyOCSPCertPathValidatorException extends Exception {
    public TrustyOCSPCertPathValidatorException() {
        super();
    }

    public TrustyOCSPCertPathValidatorException(String message, Throwable cause) {
        super(message, cause);
    }

    public TrustyOCSPCertPathValidatorException(String message) {
        super(message);
    }

    public TrustyOCSPCertPathValidatorException(Throwable cause) {
        super(cause);
    }
}
