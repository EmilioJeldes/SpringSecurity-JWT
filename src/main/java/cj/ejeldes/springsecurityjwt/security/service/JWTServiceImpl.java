package cj.ejeldes.springsecurityjwt.security.service;

import cj.ejeldes.springsecurityjwt.security.util.SimpleGrantedAuthorityMixin;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

@Service
public class JWTServiceImpl implements JWTService {

    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    @Value("${jwt.expiration}")
    private Long TOKEN_EXPIRATION;

    @Override
    public String create(Authentication authentication) throws IOException {
        // Get the user and authorities
        UserDetails user = (User) authentication.getPrincipal();
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();

        // Get claims to pass it to the token creation
        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

        // Create and return the token with Jwts.builder
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .signWith(SECRET_KEY, SignatureAlgorithm.HS512)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000L * TOKEN_EXPIRATION))
                .compact();
    }

    @Override
    public boolean validate(String token) {
        try {
            // true if its able to get the claims
            getClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // false if not
            return false;
        }
    }

    @Override
    public Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(resolve(token))
                .getBody();
    }

    @Override
    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    @Override
    public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
        Object roles = getClaims(token).get("authorities");

        return Arrays.asList(new ObjectMapper()
                                     .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
                                     .readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
    }

    @Override
    public String resolve(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.replace("Bearer ", "");
        }
        return null;
    }
}
