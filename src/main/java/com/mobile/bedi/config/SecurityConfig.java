package com.mobile.bedi.config;

import com.mobile.bedi.jwt.*;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 의존성 주입
    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this. jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers("/h2-console/**", "/favicon.ico");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

       http
               .csrf().disable()

               // 예외 핸들링
               .exceptionHandling()
               .authenticationEntryPoint(jwtAuthenticationEntryPoint)
               .accessDeniedHandler(jwtAccessDeniedHandler)

               // 세션 사용 안함
               .and()
                .sessionManagement()
               .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

               // 토큰이 들어오지 않는 /auth/google 에 대한 요청은 모두 허용
               // 나머지 요청은 모두 인증증
               .and()
                .authorizeRequests()
               .antMatchers("/auth/google").permitAll()
               .anyRequest().authenticated()

               // jwt 필터 설정
               .and()
               .apply(new JwtSecurityConfig(tokenProvider));
    }

}
