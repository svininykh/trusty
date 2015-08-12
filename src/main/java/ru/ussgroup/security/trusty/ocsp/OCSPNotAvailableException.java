package ru.ussgroup.security.trusty.ocsp;

public class OCSPNotAvailableException extends Exception {
	private static final long serialVersionUID = 1L;

	public OCSPNotAvailableException() {
		super();
	}

	public OCSPNotAvailableException(String message, Throwable cause) {
		super(message, cause);
	}

	public OCSPNotAvailableException(String message) {
		super(message);
	}

	public OCSPNotAvailableException(Throwable cause) {
		super(cause);
	}
}
