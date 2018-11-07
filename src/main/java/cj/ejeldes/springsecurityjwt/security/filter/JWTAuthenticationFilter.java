package cj.ejeldes.springsecurityjwt.security.filter;

import cj.ejeldes.springsecurityjwt.entities.security.Usuario;
import cj.ejeldes.springsecurityjwt.security.service.JWTService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    private final JWTService jwtService;
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager,
                                   JWTService jwtService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
    }

    // ~ Attemp to authenticate
    // ===================================================================================================
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // If form data
        if (password != null && username != null) {
            logger.info("Username login: '" + username + "' form:data");
            logger.info("Password login: '" + password + "' form:data");
        } else {
            // If Raw Json
            Usuario usuario = null;
            try {
                usuario = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
                username = usuario.getUsername();
                password = usuario.getPassword();

                logger.info("Username login: '" + username + "' raw:data");
                logger.info("Password login: '" + password + "' raw:data");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (username == null) username = "";
        if (password == null) password = "";

        username = username.trim();

        // authToken used by spring security to be manage internally after success authentication
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authToken);
    }

    // ~ On authentication successful
    // ===================================================================================================
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        // Create the token and the user from the Authentication
        String token = jwtService.create(authResult);
        User user = (User) authResult.getPrincipal();

        // Pass token into the header
        response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);

        // Create a map json with the token and the user
        Map<String, Object> body = new HashMap<>();
        body.put("token", token);
        body.put("user", user);
        body.put("mensaje", "Hola " + user.getUsername() + " has iniciado sesión con exito");

        // Pass the token, status and content type to the response
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }

    // ~ On authentication failure
    // ===================================================================================================
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        // Create a map json with the error and the message
        Map<String, Object> body = new HashMap<>();
        body.put("mensaje", "username o passoword incorrectos");
        body.put("error", failed.getMessage());

        // Pass the body and sets content type and status
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }
}
