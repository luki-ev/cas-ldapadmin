package de.jalin.cas.ldap;

public interface UsernamePasswordValidator {

	public boolean isAuthenticated(String user, String passwd) throws PasswordValidationException;
	
}
