package de.jalin.cas.ldap;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.FailedLoginException;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.CoreAuthenticationUtils;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;

public class LdapAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

	private final LDAPPasswordValidator ldapPasswordValidator;

	public LdapAuthenticationHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory) {
		super(name, servicesManager, principalFactory, Integer.MAX_VALUE);
		ldapPasswordValidator = new LDAPPasswordValidator();
	}

	public void setLdapProviderURL(final String ldapProviderURL) {
		this.ldapPasswordValidator.setLdapProviderURL(ldapProviderURL);
	}

	public void setLdapStartTLS(final boolean ldapStartTLS) {
		this.ldapPasswordValidator.setLdapStartTLS(ldapStartTLS);
	}

	public void setLdapUserDC(final String ldapUserDC) {
		this.ldapPasswordValidator.setLdapUserDC(ldapUserDC);
	}

	public void setLdapGroupsDC(final String ldapGroupsDC) {
		this.ldapPasswordValidator.setLdapGroupsDC(ldapGroupsDC);
	}

	@Override
	protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword)
			throws GeneralSecurityException, PreventedException {
		final String username = credential.getUsername();
		final String password = credential.getPassword();
		try {
			if (!ldapPasswordValidator.isAuthenticated(username, password)) {
				throw new FailedLoginException("login failed");
			}
		} catch (PasswordValidationException e) {
			throw new FailedLoginException(e.getMessage());
		}
		final Map<String, Object> attribsMap = new HashMap<String, Object>();
		if (username.startsWith("hsh00-")) {
			attribsMap.put("groups", username.substring(6) + ", member");
		} else {
			if (username.length() >= 5) {
				attribsMap.put("groups", username.substring(0, 5) + ", " + username.substring(0, 3));
			}
		}
		final Map<String, List<Object>> attributes = CoreAuthenticationUtils.convertAttributeValuesToMultiValuedObjects(attribsMap);
		final Principal principal = this.principalFactory.createPrincipal(username, attributes);
		return createHandlerResult(credential, principal);
	}
	
}
