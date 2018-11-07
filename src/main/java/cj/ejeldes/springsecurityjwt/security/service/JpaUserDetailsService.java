package cj.ejeldes.springsecurityjwt.security.service;

import cj.ejeldes.springsecurityjwt.entities.security.Usuario;
import cj.ejeldes.springsecurityjwt.repository.UsuarioRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    public JpaUserDetailsService(UsuarioRepository usuarioRepository) {this.usuarioRepository = usuarioRepository;}

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Usuario usuario = usuarioRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("No existe el usuario '" + username + "' en el sistema"));

        Set<GrantedAuthority> authorities = usuario.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
                .collect(Collectors.toSet());

        if (authorities.isEmpty()) {
            throw new UsernameNotFoundException("No existe el usuario '" + username + "' en el sistema");
        }

        return new User(usuario.getUsername(), usuario.getPassword(), authorities);
    }
}
