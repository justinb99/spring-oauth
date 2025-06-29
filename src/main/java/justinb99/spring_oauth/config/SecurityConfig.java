package justinb99.spring_oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import java.net.URI;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange(exchanges -> exchanges
                .anyExchange().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .authenticationSuccessHandler((webFilterExchange, authentication) -> {
                    webFilterExchange.getExchange().getResponse().setStatusCode(
                        org.springframework.http.HttpStatus.FOUND);
                    webFilterExchange.getExchange().getResponse().getHeaders().add("Location", "/");
                    return webFilterExchange.getExchange().getResponse().setComplete();
                })
            )
            .logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler())
            )
            .build();
    }

    @Bean
    public ServerLogoutSuccessHandler oidcLogoutSuccessHandler() {
        return (exchange, authentication) -> {
            String logoutUrl = "http://localhost:9999/realms/spring-oauth/protocol/openid-connect/logout";
            String redirectUri = "http://localhost:8080";

            if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
              if (oauthToken.getPrincipal() instanceof OidcUser oidcUser) {
                String idToken = oidcUser.getIdToken().getTokenValue();
                    logoutUrl += "?id_token_hint=" + idToken + "&post_logout_redirect_uri=" + redirectUri;
                } else {
                    logoutUrl += "?post_logout_redirect_uri=" + redirectUri;
                }
            } else {
                logoutUrl += "?post_logout_redirect_uri=" + redirectUri;
            }

            exchange.getExchange().getResponse().setStatusCode(org.springframework.http.HttpStatus.FOUND);
            exchange.getExchange().getResponse().getHeaders().setLocation(URI.create(logoutUrl));
            return exchange.getExchange().getResponse().setComplete();
        };
    }
}