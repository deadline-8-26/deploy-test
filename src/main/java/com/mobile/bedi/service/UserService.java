package com.mobile.bedi.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.mobile.bedi.entity.Authority;
import com.mobile.bedi.entity.RefreshToken;
import com.mobile.bedi.entity.User;
import com.mobile.bedi.jwt.TokenProvider;
import com.mobile.bedi.repository.RefreshTokenRepository;
import com.mobile.bedi.repository.UserRepository;
import com.mobile.bedi.repository.dto.TokenDto;
import com.mobile.bedi.util.SecurityUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Optional;

@Slf4j
@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
            // Specify the CLIENT_ID of the app that accesses the backend:
            .setAudience(Collections.singletonList("24418312077-pu3t75in2eeo4o519hvvcick5mgf5h96.apps.googleusercontent.com"))
            // Or, if multiple clients access the backend:
            //.setAudience(Arrays.asList(CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3))
            .build();

    @Transactional
    public User signup(String credential) throws GeneralSecurityException, IOException {
        User user = getUser(credential);
        if (userRepository.findById(user.getId()).orElse(null) != null) {
            log.debug("이미 가입되어 있는 유저입니다.");
        }
        return userRepository.save(user);
    }

    @Transactional
    public TokenDto login(User user) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(user.getId(), user.getId());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        TokenDto tokenDto = tokenProvider.createToken(authentication);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(tokenDto.getRefreshToken())
                .user(user)
                .expiration(tokenDto.getRefreshTokenExpiresIn())
                .build();

        refreshTokenRepository.save(refreshToken);

        return tokenDto;
    }

    @Transactional
    public Optional<User> getUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findById);
    }

    private User getUser(String credential) throws GeneralSecurityException, IOException {

        String idTokenString = credential;
        GoogleIdToken idToken = verifier.verify(idTokenString);

        if (idToken != null) {
            GoogleIdToken.Payload payload = idToken.getPayload();

            // user identifier
            String userId = payload.getSubject();

            // Get profile information from payload
            String name = (String) payload.get("name");
            String email = payload.getEmail();

            // user id를 password로 설정
            return User.builder()
                    .id(userId)
                    .name(name)
                    .email(email)
                    .password(passwordEncoder.encode(userId))
                    .authority(Authority.GOOGLE)
                    .build();
        } else {
            log.debug("구글 ID 토큰이 유효하지 않습니다.");
        }
        return null;
    }
}


