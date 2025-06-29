package justinb99.spring_oauth.controllers;

import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import reactor.core.publisher.Mono;

@Controller
public class HomeController {

    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

    public HomeController(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/")
    public Mono<String> index(
            @AuthenticationPrincipal OAuth2User principal,
            OAuth2AuthenticationToken authentication,
            Model model,
            ServerHttpResponse response) {
        
        // Set no-cache headers
        response.getHeaders().add("Cache-Control", "no-cache, no-store, must-revalidate");
        response.getHeaders().add("Pragma", "no-cache");
        response.getHeaders().add("Expires", "0");
        
        return authorizedClientService
                .loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName())
                .map(authorizedClient -> {
                    var name = principal.getAttribute("name");
                    var email = principal.getAttribute("email");
                    var accessToken = authorizedClient.getAccessToken().getTokenValue();
                    
                    model.addAttribute("name", name);
                    model.addAttribute("email", email);
                    model.addAttribute("accessToken", accessToken);
                    
                    return "index";
                });
    }
}