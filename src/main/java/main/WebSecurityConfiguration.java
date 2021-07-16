package main;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.Builder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@Configuration
@EnableWebSecurity
@PropertySource("classpath:application.properties")
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";

    Logger logger = LoggerFactory.getLogger(WebSecurityConfiguration.class);

    @Autowired
    private Environment env;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ClientRegistrationRepository repo = clientRegistrationRepository();
        http.authorizeRequests()
                .antMatchers("/oauth_login", "/")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .defaultSuccessUrl("/loginSuccess", true)
                .failureUrl("/loginFailure")
                .loginPage("/oauth_login")
                .clientRegistrationRepository(repo)
                .authorizedClientService(authorizedClientService());
        // .authorizationEndpoint()
        // .baseUri("/login/oauth/authorize")
        // .authorizationRequestRepository(authorizationRequestRepository());
    }

    public ClientRegistrationRepository clientRegistrationRepository() {
        String clientId = env.getProperty(CLIENT_PROPERTY_KEY + "github." + "client-id");
        String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + "github." + "client-secret");
        ClientRegistration reg = getBuilder("GitHub").clientId(clientId).clientSecret(clientSecret).build();

        return new InMemoryClientRegistrationRepository(reg);
    }
    
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

    private static final String DEFAULT_REDIRECT_URL = "https://localhost:8091/oauth2/authorization/github";

    public Builder getBuilder(String registrationId) {
        ClientRegistration.Builder builder = getBuilder(registrationId,
                ClientAuthenticationMethod.BASIC, DEFAULT_REDIRECT_URL);
        builder.scope("read:user");
        builder.authorizationUri("https://github.com/login/oauth/authorize");
        builder.tokenUri("https://github.com/login/oauth/access_token");
        builder.userInfoUri("https://api.github.com/user");
        builder.userNameAttributeName("id");
        builder.clientName("GitHub");
        return builder;
    }

    protected final ClientRegistration.Builder getBuilder(String registrationId,
            ClientAuthenticationMethod method, String redirectUri) {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
        builder.clientAuthenticationMethod(method);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.redirectUriTemplate(redirectUri);
        return builder;
    }

    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(
                clientRegistrationRepository());
    }
}
