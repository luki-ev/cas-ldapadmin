package de.jalin.cas.ldap;

public class PasswordValidationException extends Exception {

	private static final long serialVersionUID = 1L;

	public PasswordValidationException(final String message) {
		super(message);
	}

	public PasswordValidationException(final Throwable excption) {
		super(excption);
	}

	public PasswordValidationException(final String message, final Throwable exception) {
		super(message, exception);
	}

}