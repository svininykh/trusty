package ru.ussgroup.security.trusty.ocsp;

public class OCSPNonceException extends Exception {
	private static final long serialVersionUID = 1L;

	public OCSPNonceException() {
		super();
	}

	public OCSPNonceException(String message, Throwable cause) {
		super(message, cause);
	}

	public OCSPNonceException(String message) {
		super(message);
	}

	public OCSPNonceException(Throwable cause) {
		super(cause);
	}
}
