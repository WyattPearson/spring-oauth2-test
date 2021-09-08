package github.test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

@Configuration
@EnableWebSecurity(debug = true)
@Import({ MainWebAppAppConfiguration.class })
public class SecurityConfig {

    @Configuration
    @Order(4)
    public static class AuthConfiguration extends WebSecurityConfigurerAdapter {
        @Autowired
        ClientRegistrationRepository clientRegRepo;

        @Autowired
        OAuth2AuthorizedClientService clientService;

        @Autowired
        OAuth2AuthorizedClientRepository authorizedClientRepository;

        private static final String REDIRECT_URL = "/test/success";

        private static final String FAILURE_URL = "/failure";

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/**").csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/oauth_login")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                    .and()
                    .oauth2Login()
                    .defaultSuccessUrl(REDIRECT_URL)
                    .failureUrl(FAILURE_URL)
                    // .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/oauth_login")).and()
                    .clientRegistrationRepository(clientRegRepo);
            // .redirectionEndpoint(redirectionEndpoint -> redirectionEndpoint.baseUri(REDIRECT_URL));
            // .and()
            // .oauth2ResourceServer(oauth2 -> oauth2.jwt());
        }
    }

    // @Configuration
    // @Order(5)
    // public static class AuthConfiguration2 extends WebSecurityConfigurerAdapter {
    //
    // @Override
    // protected void configure(HttpSecurity http) throws Exception {
    // http.antMatcher("/test/**")
    // .authorizeRequests()
    // .anyRequest().authenticated();
    // }
    // }
}
