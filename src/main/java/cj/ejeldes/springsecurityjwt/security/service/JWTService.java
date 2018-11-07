package cj.ejeldes.springsecurityjwt.security.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.Collection;

public interface JWTService {

    /**
     * Creates a Jwt from an authentication object
     *
     * @param authentication passed through the <code>AuthenticationManager</code>
     * @return a Jwt from the <code>Authentication</code>
     * @throws JsonProcessingException in case of error parsing the body of the token
     */
    String create(Authentication authentication) throws IOException;

    /**
     * Given a specific token, it validates: if exist and if its a Bearer type from the encoded token
     *
     * @param token a Jwt
     * @return <code>true</code> if its valid or <code>false</code> if not
     */
    boolean validate(String token);

    /**
     * Given a specific token, it return the content body from the encoded token
     *
     * @param token a Jwt
     * @return the <code>Claims</code> object with the content
     */
    Claims getClaims(String token);

    /**
     * Given a specfic token, it returns the username from the encoded token
     *
     * @param token a Jwt
     * @return <code>String</code> username
     */
    String getUsername(String token);

    /**
     * Given a specific token, it returns the roles a from the content body of the encoded token
     *
     * @param token a Jwt
     * @return <code>Collection</code> of <code>GrantedAuthority</code> roles
     */
    Collection<? extends GrantedAuthority> getRoles(String token) throws IOException;

    /**
     * Given a specific token, removes the "Bearer " part and just returns the encoded part
     *
     * @param token a Jwt
     * @return <code>String</code> resolved token
     */
    String resolve(String token);
}
