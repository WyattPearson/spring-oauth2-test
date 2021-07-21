package github.test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@Order(Ordered.LOWEST_PRECEDENCE)
@EnableWebSecurity
@Import({ MainWebAppAppConfiguration.class })
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    ClientRegistrationRepository clientRegRepo;

    @Autowired
    OAuth2AuthorizedClientService clientService;

    @Autowired
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenClient;

    @Autowired
    AuthenticationSuccessHandler successHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/oauth_login")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .successHandler(successHandler)
                .loginPage("/oauth_login")
                .clientRegistrationRepository(clientRegRepo)
                .authorizedClientService(clientService)
                .tokenEndpoint()
                .accessTokenResponseClient(tokenClient);
    }
}
