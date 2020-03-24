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
		this.ldapPasswordValidator.setLdapUsersDC(ldapUserDC);
	}

	public void setLdapGroupsDC(final String ldapGroupsDC) {
		this.ldapPasswordValidator.setLdapGroupsDC(ldapGroupsDC);
	}

	public void setLdapBindCredentials(final String ldapBindUser, final String ldapBindPassword) {
		this.ldapPasswordValidator.setLdapBindUser(ldapBindUser);
		this.ldapPasswordValidator.setLdapBindPassword(ldapBindPassword);
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
			final Map<String, String> accountAttributes = ldapPasswordValidator.accountAttributes(username);
			final Map<String, Object> attribsMap = new HashMap<String, Object>();
			for (String key : accountAttributes.keySet()) {
				attribsMap.put(key, accountAttributes.get(key));
			}
			final Map<String, List<Object>> attributes = CoreAuthenticationUtils.convertAttributeValuesToMultiValuedObjects(attribsMap);
			final Principal principal = this.principalFactory.createPrincipal(username, attributes);
			return createHandlerResult(credential, principal);
		} catch (PasswordValidationException e) {
			throw new FailedLoginException(e.getMessage());
		}
	}
	
}
