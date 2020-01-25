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
	 	
	    final ServicesManager serviceManagerObject = servicesManager.getObject();
		final PrincipalFactory ldapAuthenticationPrincipalFactory = ldapAuthenticationPrincipalFactory();
		final AuthenticationHandler authenticationHandler = new LdapAuthenticationHandler(name, serviceManagerObject, ldapAuthenticationPrincipalFactory);
        return authenticationHandler;
	    }
	
	@Override
	public void configureAuthenticationExecutionPlan(AuthenticationEventExecutionPlan plan) {
		plan.registerAuthenticationHandler(myAuthenticationHandler());
	}

}
