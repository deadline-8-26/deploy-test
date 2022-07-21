package com.mobile.bedi.entity;


import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter @Setter
@NoArgsConstructor
public class RefreshToken {

    @Id
    @Column (name = "refresh_token_id")
    private String token;

    @OneToOne (fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column (name = "refresh_token_expiration")
    private Long expiration;

    @Builder
    private RefreshToken(String token, User user, Long expiration) {
        this.token = token;
        this.user = user;
        this.expiration = expiration;
    }

}
