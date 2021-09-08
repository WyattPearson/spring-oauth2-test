package github.test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.Builder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

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

    private static final String REDIRECT_URL = "{baseUrl}/login/oauth2/code/{registrationId}";

    private static final String OKTA_DEV_URI = "https://dev-1442531.okta.com";

    private final static String OKTA_DEV_DEFAULT_URI = OKTA_DEV_URI + "/oauth2/default/v1";

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration gitHubReg = getGitHubReg();
        // ClientRegistration oktaReg = getOktaReg();
        return new InMemoryClientRegistrationRepository(gitHubReg);
    }

    private ClientRegistration getGitHubReg() {
        String clientId = env.getProperty(GITHUB_CLIENT_ID);
        String clientSecret = env.getProperty(GITHUB_CLIENT_SECRET);
        return getBuilderGithub("github").clientId(clientId).clientSecret(clientSecret).build();
    }

    private Builder getBuilderGithub(String registrationId) {
        ClientRegistration.Builder builder = getBuilder(registrationId,
                ClientAuthenticationMethod.BASIC);
        builder.scope("read:user");
        builder.authorizationUri("https://github.com/login/oauth/authorize");
        builder.tokenUri("https://github.com/login/oauth/access_token");
        builder.userInfoUri("https://api.github.com/user");
        builder.userNameAttributeName("id");
        builder.clientName("GitHub");
        return builder;
    }

    private ClientRegistration.Builder getBuilder(String registrationId,
            ClientAuthenticationMethod method) {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
        builder.clientAuthenticationMethod(method);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.redirectUriTemplate(REDIRECT_URL);
        return builder;
    }

    // @Bean
    // public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository regRepo) {
    // return new InMemoryOAuth2AuthorizedClientService(regRepo);
    // }
    //
    // @Bean
    // public OAuth2AuthorizedClientRepository authorizedClientRepository(
    // OAuth2AuthorizedClientService authorizedClientService) {
    // return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    // }
    //
    // @Bean
    // WebClient webClient(ClientRegistrationRepository clientRegistrationRepository,
    // OAuth2AuthorizedClientRepository authorizedClientRepository) {
    // ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new
    // ServletOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrationRepository,
    // authorizedClientRepository);
    // oauth2.setDefaultOAuth2AuthorizedClient(true);
    // return WebClient.builder().apply(oauth2.oauth2Configuration()).build();
    // }
    //
    // @Bean
    // WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
    // ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client = new
    // ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
    // return WebClient.builder()
    // .apply(oauth2Client.oauth2Configuration())
    // .build();
    // }
    //
    // @Bean
    // OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
    // OAuth2AuthorizedClientRepository authorizedClientRepository) {
    // OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
    // .authorizationCode()
    // .refreshToken()
    // .clientCredentials()
    // .password()
    // .build();
    // DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
    // clientRegistrationRepository, authorizedClientRepository);
    // authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
    //
    // // For the `password` grant, the `username` and `password` are supplied via request parameters,
    // // so map it to `OAuth2AuthorizationContext.getAttributes()`.
    // authorizedClientManager.setContextAttributesMapper(contextAttributesMapper());
    //
    // return authorizedClientManager;
    // }
    //
    // private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {
    // return authorizeRequest -> {
    // Map<String, Object> contextAttributes = Collections.emptyMap();
    // HttpServletRequest servletRequest = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
    // String username = servletRequest.getParameter(OAuth2ParameterNames.USERNAME);
    // String password = servletRequest.getParameter(OAuth2ParameterNames.PASSWORD);
    // if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
    // contextAttributes = new HashMap<>();
    //
    // // `PasswordOAuth2AuthorizedClientProvider` requires both attributes
    // contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
    // contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
    // }
    // return contextAttributes;
    // };
    // }
    //
    // @Bean
    // public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
    // DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new
    // DefaultAuthorizationCodeTokenResponseClient();
    // return accessTokenResponseClient;
    // }
    //
    // @Bean
    // public AuthenticationSuccessHandler authenticationSuccessHandler() {
    // return new CustomAuthenticationSuccessHandler();
    // }
    //
    // @Bean
    // public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
    // return new HttpSessionOAuth2AuthorizationRequestRepository();
    // }

    // private ClientRegistration getOktaReg() {
    // String clientId = env.getProperty(OKTA_CLIENT_ID);
    // String clientSecret = env.getProperty(OKTA_CLIENT_SECRET);
    // return getBuilderOkta("okta").clientId(clientId).clientSecret(clientSecret).build();
    // }
    //
    // private Builder getBuilderOkta(String registrationId) {
    // ClientRegistration.Builder builder = getBuilder(registrationId,
    // ClientAuthenticationMethod.POST);
    //
    // builder.scope("openid", "profile", "email");
    // builder.authorizationUri(OKTA_DEV_DEFAULT_URI + "/authorize");
    // builder.tokenUri(OKTA_DEV_DEFAULT_URI + "/token");
    // builder.userInfoUri(OKTA_DEV_DEFAULT_URI + "/userinfo");
    // builder.userNameAttributeName(IdTokenClaimNames.SUB);
    // builder.clientName("Okta");
    // return builder;
    // }

}
