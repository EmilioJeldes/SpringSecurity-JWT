package cj.ejeldes.springsecurityjwt.security.filter;

import cj.ejeldes.springsecurityjwt.security.service.JWTService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private final JWTService jwtService;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
        super(authenticationManager);
        this.jwtService = jwtService;
    }

    // ~ On every request
    // ===================================================================================================
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        // Gets the header "Authorization"
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Validates type "Bearer " otherwise continues with the filter chain
        if (!isBearer(header)) {
            chain.doFilter(request, response);
            return;
        }

        // Initialize authentication
        UsernamePasswordAuthenticationToken authentication = null;

        // If the token is valid, it gets:
        if (jwtService.validate(header)) {

            // the username and authorities
            String username = jwtService.getUsername(header);
            Collection<? extends GrantedAuthority> authorities = jwtService.getRoles(header);

            // Creates the authentication Object from the token
            authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        }

        // Pass the authentication to the security context
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private boolean isBearer(String header) {
        return header == null || header.startsWith("Bearer ");
    }
}
