package cj.ejeldes.springsecurityjwt.entities.security;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.List;

@Data
@Entity
@Table(name = "users")
@NoArgsConstructor
public class Usuario implements Serializable {

    private static final long serialVersionUID = -7650770525722112455L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String username;

    private String password;

    @Temporal(TemporalType.DATE)
    private Date createAt;
    private Boolean enabled;

    @OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "user_id")
    private List<Role> roles;

    @PrePersist
    public void prePersist() {
        this.createAt = new Date();
    }
}
