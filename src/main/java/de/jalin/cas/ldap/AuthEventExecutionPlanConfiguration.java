package de.jalin.cas.ldap;

import java.util.List;

import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.core.authentication.AuthenticationProperties;
import org.apereo.cas.configuration.model.support.ldap.LdapAuthenticationProperties;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;

public class AuthEventExecutionPlanConfiguration implements AuthenticationEventExecutionPlanConfigurer {

    @Autowired
    @Qualifier("servicesManager")
    private ObjectProvider<ServicesManager> servicesManager;

    @Autowired
    @Qualifier("defaultPrincipalResolver")
    private ObjectProvider<PrincipalResolver> defaultPrincipalResolver;

    @Autowired
    private CasConfigurationProperties casProperties;

    @ConditionalOnMissingBean(name = "ldapAuthenticationPrincipalFactory")
    @Bean
    @RefreshScope
    public PrincipalFactory ldapAuthenticationPrincipalFactory() {
        return PrincipalFactoryUtils.newPrincipalFactory();
    }
    
    
	@Bean
	public AuthenticationHandler myAuthenticationHandler() {
	 	final String name = "LDAP Authentication";
	 	final AuthenticationProperties authenticationProperties = casProperties.getAuthn();
	 	final List<LdapAuthenticationProperties> ldapPropertiesList = authenticationProperties.getLdap();
	 	final LdapAuthenticationProperties ldapAuthenticationProperties = ldapPropertiesList.get(0);
	 	
	 	final String ldapUrl = ldapAuthenticationProperties.getLdapUrl();
	 	// System.out.println("====> ldap-url: " + ldapUrl);

	 	final String ldapBaseDN = ldapAuthenticationProperties.getBaseDn();
	 	// System.out.println("====> base-dn: " + ldapBaseDN);
	 	
	 	final String ldapBindDN = ldapAuthenticationProperties.getBindDn();
	 	// System.out.println("====> bind-dn: " + ldapBindDN);
	 	
	 	final String ldapBindPw = ldapAuthenticationProperties.getBindCredential();
	 	// System.out.println("====> bind-credential: " + ldapBindPw);
	 	
	 	final boolean ldapStartTLS = ldapAuthenticationProperties.isUseStartTls();
	 	// System.out.println("====> use-start-tls: " + ldapStartTLS);
	 	
	 	final ServicesManager serviceManagerObject = servicesManager.getObject();
		final PrincipalFactory ldapAuthenticationPrincipalFactory = ldapAuthenticationPrincipalFactory();
		final LdapAuthenticationHandler authenticationHandler = new LdapAuthenticationHandler(name, serviceManagerObject, ldapAuthenticationPrincipalFactory);
		authenticationHandler.setLdapProviderURL(ldapUrl);
		authenticationHandler.setLdapStartTLS(ldapStartTLS);
		authenticationHandler.setLdapUserDC("uid={user},ou=users," + ldapBaseDN);
		authenticationHandler.setLdapGroupsDC("ou=groups," + ldapBaseDN);
		authenticationHandler.setLdapBindCredentials(ldapBindDN, ldapBindPw);
        return authenticationHandler;
	    }
	
	@Override
	public void configureAuthenticationExecutionPlan(AuthenticationEventExecutionPlan plan) {
		plan.registerAuthenticationHandler(myAuthenticationHandler());
	}

}
