package com.example.learnspringsecurity.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

//@Configuration
public class BasicAuthSecurityConfiguration { // 필터 체인 설정 가능.
    @Bean
    @Order(2147483642)
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((requests) -> {
//            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.anyRequest()).authenticated();
//        });

        http.authorizeHttpRequests(
                auth -> {
                    auth.anyRequest().authenticated();
                }
        ); // 모든 요청을 인증.

        http.sessionManagement(
                session -> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS // 세션(쿠키)을 절대 생성하지 않음.
                ) // 세션 정책 설정.
        );

//        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());

        http.csrf().disable(); // csrf 비활성화
        http.headers().frameOptions().sameOrigin();
// 요청이 동일한 오리진에서 오는 경우, 해당 app의 frame을 허용함.
// example.com은 OK. evil.com은 허용 X.
        return (SecurityFilterChain) http.build();
    }

    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();

        // JdbcDaoImpl 클래스의 DEFAULT_USER_SCHEMA_DDL_LOCATION에 기본적으로 ddl이 설정돼있음.
        // 기본적인 스키마가 생성됨
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){

        var user = User.withUsername("gnues")
                //.password("{noop}dummy")
                .password("dummy")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("USER").build();
        var admin = User.withUsername("admin")
                .password("dummy")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("ADMIN").build();

        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
        // 해싱함수 수행. 강도 매개변수가 클수록 패스워드를 해싱하는데 필요한 작업이 기하급수적으로 증가함..!(기본값 10)
    }


}
