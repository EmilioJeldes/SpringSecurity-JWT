package cj.ejeldes.springsecurityjwt.config;

import cj.ejeldes.springsecurityjwt.security.filter.JWTAuthenticationFilter;
import cj.ejeldes.springsecurityjwt.security.filter.JWTAuthorizationFilter;
import cj.ejeldes.springsecurityjwt.security.service.JWTService;
import cj.ejeldes.springsecurityjwt.security.service.JpaUserDetailsService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private final BCryptPasswordEncoder passwordEncoder;
    private final JpaUserDetailsService jpaUserDetailsService;
    private final JWTService jwtService;


    public SpringSecurityConfig(BCryptPasswordEncoder passwordEncoder,
                                JpaUserDetailsService jpaUserDetailsService,
                                JWTService jwtService) {
        this.passwordEncoder = passwordEncoder;
        this.jpaUserDetailsService = jpaUserDetailsService;
        this.jwtService = jwtService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jpaUserDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/public", "/api").permitAll()
                .antMatchers("/private", "/user/**").hasAnyRole("USER")
                .antMatchers("/admin").hasAnyRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtService))
                .addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService))
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}
