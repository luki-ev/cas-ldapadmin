package de.jalin.cas.ldap;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


public class LDAPPasswordValidator implements UsernamePasswordValidator {

	private String ldapProviderURL = "ldap://ldap.example.com/";
	private String ldapUsersDC = "ou=users,dc=example,dc=com";
	private String ldapGroupsDC = "ou=groups,dc=example,dc=com";
	private String ldapBindUser = "uid=system,ou=bind";
	private String ldapBindPassword = "secret";
	private boolean isLdapStartTLS = false;
	
	public LDAPPasswordValidator() { }
	
	public String getLdapProviderURL() {
		return ldapProviderURL;
	}

	public void setLdapProviderURL(String ldapProviderURL) {
		this.ldapProviderURL = ldapProviderURL;
	}

	public String getLdapUsersDC() {
		return ldapUsersDC;
	}

	public void setLdapUsersDC(String ldapUsersDC) {
		this.ldapUsersDC = ldapUsersDC;
	}

	public String getLdapGroupsDC() {
		return ldapGroupsDC;
	}

	public void setLdapGroupsDC(String ldapGroupsDC) {
		this.ldapGroupsDC = ldapGroupsDC;
	}

	public boolean isLdapStartTLS() {
		return isLdapStartTLS;
	}

	public void setLdapStartTLS(boolean isLdapStartTLS) {
		this.isLdapStartTLS = isLdapStartTLS;
	}

	public String getLdapBindUser() {
		return ldapBindUser;
	}

	public void setLdapBindUser(String ldapBindUser) {
		this.ldapBindUser = ldapBindUser;
	}

	public String getLdapBindPassword() {
		return ldapBindPassword;
	}

	public void setLdapBindPassword(String ldapBindPassword) {
		this.ldapBindPassword = ldapBindPassword;
	}

	@Override
	public boolean isAuthenticated(final String user, final String passwd) throws PasswordValidationException {
		try {
			if (user.equals(user.toLowerCase())) {
				return false;
			}
			final InitialLdapContext ctx = initializeContext();
			String principal = "uid=" + user +  "," + getLdapUsersDC();
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, principal);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, passwd);
			try {
				ctx.reconnect(null);
			} catch (AuthenticationException e) {
				ctx.close();
				return false;
			}
			ctx.close();
			return true;
		} catch (NamingException e) {
			throw new PasswordValidationException(e.getMessage());
		}
	}

	public Map<String, String> accountAttributes(final String uid) throws PasswordValidationException {
		try {
			final InitialLdapContext ctx = initializeContext();
			final String principal = getLdapBindUser();
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, principal);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, getLdapBindPassword());
			final StringBuffer listOfGroups = new StringBuffer();
            final Attributes matchingAttributes1 = new BasicAttributes();
            matchingAttributes1.put("uniqueMember", "uid=" + uid + "," + getLdapUsersDC());
            final NamingEnumeration<SearchResult> searchResult1 = ctx.search(getLdapGroupsDC(), matchingAttributes1);
            while (searchResult1.hasMore()) {
            	final SearchResult node = searchResult1.next();
            	final String nodeName = node.getName();
            	if (nodeName != null && nodeName.startsWith("cn=")) {
            		if (listOfGroups.length() > 0) {
            			listOfGroups.append(", ");
            		}
            		listOfGroups.append(nodeName.substring(3));
            	}
            }
            final Attributes matchingAttributes2 = new BasicAttributes();
            matchingAttributes2.put("member", "uid=" + uid + "," + getLdapUsersDC());
            final NamingEnumeration<SearchResult> searchResult2 = ctx.search(getLdapGroupsDC(), matchingAttributes2);
            while (searchResult2.hasMore()) {
            	final SearchResult node = searchResult2.next();
            	final String nodeName = node.getName();
            	if (nodeName != null && nodeName.startsWith("cn=")) {
            		if (listOfGroups.length() > 0) {
            			listOfGroups.append(", ");
            		}
            		listOfGroups.append(nodeName.substring(3));
            	}
            }
            final Attributes userAttributes = ctx.getAttributes("uid="+ uid + "," + getLdapUsersDC());
            final Map<String, String> ldapAccount = new HashMap<String, String>();
            ldapAccount.put("groups", listOfGroups.toString());
            ldapAccount.put("mail", extractAttribute(userAttributes, "mail").toString());
            ldapAccount.put("cn", extractAttribute(userAttributes, "cn").toString());
			return ldapAccount;
		} catch (NamingException e) {
			throw new PasswordValidationException(e);
		}
	}

	private StringBuffer extractAttribute(final Attributes userAttributes, final String attributeName) throws NamingException {
		final NamingEnumeration<?> mailAttribs = userAttributes.get(attributeName).getAll();
		final StringBuffer mailAttrib = new StringBuffer();
		while (mailAttribs.hasMore()) {
			final Object object = mailAttribs.next();
			if (object != null) {
				if (mailAttrib.length() > 0) {
					mailAttrib.append(", ");
				}
				mailAttrib.append(object.toString());
			}
		}
		return mailAttrib;
	}
	
	private InitialLdapContext initializeContext() throws PasswordValidationException {
		final Properties env = new Properties();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		final boolean ldapStartTLS = isLdapStartTLS();
		final String connectPool = (new Boolean(!ldapStartTLS)).toString().toLowerCase();
		env.put("com.sun.jndi.ldap.connect.pool", connectPool);
		env.put(Context.PROVIDER_URL, getLdapProviderURL());
		InitialLdapContext ctx = null;
		try {
			ctx = new InitialLdapContext(env, null);
			StartTlsResponse tls = null;
			if (ldapStartTLS) {
				tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
				final SSLContext sc = SSLContext.getInstance("TLSv1.2");
				final TrustManager tm = new X509TrustManager() {
					@Override
					public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
					}
					@Override
					public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
					}
					@Override
					public X509Certificate[] getAcceptedIssuers() {
						return new X509Certificate[0];
					}
				};
				sc.init(null, new TrustManager[] { tm } , new SecureRandom());
				final SSLSocketFactory ssf = sc.getSocketFactory();
				tls.negotiate(ssf);
			}
			ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
		} catch (KeyManagementException | NoSuchAlgorithmException | NamingException | IOException e) {
			throw new PasswordValidationException(e);
		}
		return ctx;
	}
	
}
