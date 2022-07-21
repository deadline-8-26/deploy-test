package com.mobile.bedi.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter @Setter
@NoArgsConstructor
public class User {

    @JsonIgnore
    @Id
    @Column (name = "user_id")
    private String id;

    @Column (name = "user_name")
    private String name;

    @Column (name = "email")
    private String email;

    @JsonIgnore
    @Column (name = "password")
    private String password;

    @Enumerated(EnumType.STRING)
    private Authority authority;

    @Builder
    private User(String id, String name, String email, String password, Authority authority) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.password = password;
        this.authority = authority;
    }

}
