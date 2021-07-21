package github.test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.NimbusAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.Builder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class MainWebAppAppConfiguration {

    @Autowired
    private Environment env;

    private final static String PROPERTIES_PREFIX = "spring.security.oauth2.client.registration.";

    private final static String CLIENT_ID = "client-id";

    private final static String CLIENT_SECRET = "client-secret";

    private final static String GITHUB = "github.";

    private final static String OKTA = "okta.";

    private final static String GITHUB_CLIENT_ID = PROPERTIES_PREFIX + GITHUB + CLIENT_ID;

    private final static String GITHUB_CLIENT_SECRET = PROPERTIES_PREFIX + GITHUB + CLIENT_SECRET;

    private final static String OKTA_CLIENT_ID = PROPERTIES_PREFIX + OKTA + CLIENT_ID;

    private final static String OKTA_CLIENT_SECRET = PROPERTIES_PREFIX + OKTA + CLIENT_SECRET;

    private static final String REDIRECT_URL = "https://localhost:8091/oauth2/redirect";

    private final static String GITHUB_REDIRECT_URL = REDIRECT_URL + "/github";

    private static final String OKTA_DEV_URI = "https://dev-1442531.okta.com";

    private final static String OKTA_DEV_DEFAULT_URI = OKTA_DEV_URI + "/oauth2/default/v1";

    private final static String OKTA_REDIRECT_URL = REDIRECT_URL + "/okta";

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration gitHubReg = getGitHubReg();
        ClientRegistration oktaReg = getOktaReg();
        return new InMemoryClientRegistrationRepository(gitHubReg, oktaReg);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientServiceGithub() {
        return new InMemoryOAuth2AuthorizedClientService(
                clientRegistrationRepository());
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {

        return new NimbusAuthorizationCodeTokenResponseClient();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler();
    }

    private ClientRegistration getGitHubReg() {
        String clientId = env.getProperty(GITHUB_CLIENT_ID);
        String clientSecret = env.getProperty(GITHUB_CLIENT_SECRET);
        return getBuilderGithub("github").clientId(clientId).clientSecret(clientSecret).build();
    }

    private ClientRegistration getOktaReg() {
        String clientId = env.getProperty(OKTA_CLIENT_ID);
        String clientSecret = env.getProperty(OKTA_CLIENT_SECRET);
        return getBuilderOkta("okta").clientId(clientId).clientSecret(clientSecret).build();
    }

    private Builder getBuilderOkta(String registrationId) {
        ClientRegistration.Builder builder = getBuilder(registrationId,
                ClientAuthenticationMethod.POST, OKTA_REDIRECT_URL);

        builder.scope("openid", "profile", "email");
        builder.authorizationUri(OKTA_DEV_DEFAULT_URI + "/authorize");
        builder.tokenUri(OKTA_DEV_DEFAULT_URI + "/token");
        builder.userInfoUri(OKTA_DEV_DEFAULT_URI + "/userinfo");
        builder.userNameAttributeName(IdTokenClaimNames.SUB);
        builder.clientName("Okta");
        return builder;
    }

    private Builder getBuilderGithub(String registrationId) {
        ClientRegistration.Builder builder = getBuilder(registrationId,
                ClientAuthenticationMethod.BASIC, GITHUB_REDIRECT_URL);
        builder.scope("read:user");
        builder.authorizationUri("https://github.com/login/oauth/authorize");
        builder.tokenUri("https://github.com/login/oauth/access_token");
        builder.userInfoUri("https://api.github.com/user");
        builder.userNameAttributeName("id");
        builder.clientName("GitHub");
        return builder;
    }

    private ClientRegistration.Builder getBuilder(String registrationId,
            ClientAuthenticationMethod method, String redirectUri) {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
        builder.clientAuthenticationMethod(method);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.redirectUriTemplate(redirectUri);
        return builder;
    }

}
