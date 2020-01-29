package de.jalin.cas.ldap;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class LDAPPasswordValidator implements UsernamePasswordValidator {

	private String ldapProviderURL = "ldap://localhost:30389/ou=myorg";
	private boolean ldapStartTLS = false;
	private String ldapUserDC = "uid={user},ou=users,ou=myorg";
	private String ldapGroupsDC = "ou=groups,ou=myorg";
	
	public void setLdapProviderURL(String ldapProviderURL) {
		this.ldapProviderURL = ldapProviderURL;
	}

	public void setLdapStartTLS(boolean ldapStartTLS) {
		this.ldapStartTLS = ldapStartTLS;
	}

	public void setLdapUserDC(String ldapUserDC) {
		this.ldapUserDC = ldapUserDC;
	}

	public void setLdapGroupsDC(String ldapGroupsDC) {
		this.ldapGroupsDC = ldapGroupsDC;
	}

	@Override
	public boolean isAuthenticated(final String user, final String passwd) throws PasswordValidationException {
		try {
			try {
				Thread.sleep(100L);
			} catch (InterruptedException e) {
			}
			final Properties env = new Properties();
			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			env.put("com.sun.jndi.ldap.connect.pool", "true");
			env.put(Context.PROVIDER_URL, ldapProviderURL);
			final InitialLdapContext ctx = new InitialLdapContext(env, null);
			StartTlsResponse tls = null;
			if (ldapStartTLS) {
				tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
				final SSLContext sc = SSLContext.getInstance("TLSv1.2");
				sc.init(null, null , new SecureRandom());
				final SSLSocketFactory ssf = sc.getSocketFactory();
				tls.negotiate(ssf);
			}
			ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
			String principal = ldapUserDC.replace("{user}", user);
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, principal);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, passwd);
			try {
				ctx.reconnect(null);
			} catch (AuthenticationException e) {
				if (tls != null) tls.close();
				if (ctx != null) ctx.close();
				return false;
			}
			if (tls != null) tls.close();
			if (ctx != null) ctx.close();
			return true;
		} catch (NamingException | IOException | NoSuchAlgorithmException | KeyManagementException e) {
			throw new PasswordValidationException(e.getMessage());
		}
	}

	public static void main(String[] args) {
		final UsernamePasswordValidator validator = new LDAPPasswordValidator();
		String msg = "fail";
		try {
			msg = validator.isAuthenticated("mein-Name", "mein-Passwort") ? "Ok" : "fail";
			System.out.println(msg);
		} catch (PasswordValidationException e) {
			System.out.println(msg);
			e.printStackTrace();
		}
	}

}
