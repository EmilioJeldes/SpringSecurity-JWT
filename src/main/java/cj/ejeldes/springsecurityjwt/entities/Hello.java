package cj.ejeldes.springsecurityjwt.entities;

import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
public class Hello implements Serializable {

    private String message;
    private String from;
    private String to;
    private Date createAt;

    public Hello() {
        this.createAt = new Date();
    }
}
