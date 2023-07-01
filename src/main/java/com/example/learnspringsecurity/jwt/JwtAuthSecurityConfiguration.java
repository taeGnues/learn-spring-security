package com.example.learnspringsecurity.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;


//@Configuration
public class JwtAuthSecurityConfiguration { // 필터 체인 설정 가능.

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
// SecurityFilterChain이 요청을 인증하게 되고, JWT를 검증하는 역할을 함.
        http.authorizeHttpRequests(
                auth -> {
                    auth.anyRequest().authenticated();
                });// 모든 요청을 인증.

        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS)// 세션(쿠키)을 절대 생성하지 않음.
        );// 세션 정책 설정.

//        http.formLogin(Customizer.withDefaults());
        http.httpBasic();

        http.csrf().disable(); // csrf 비활성화

        http.headers().frameOptions().sameOrigin();

     //   http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
// 요청이 동일한 오리진에서 오는 경우, 해당 app의 frame을 허용함.
// example.com은 OK. evil.com은 허용 X.
        return http.build();
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
        // encoding 수행.

        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
        // 해싱함수 수행. 강도 매개변수가 클수록
        // 패스워드를 해싱하는데 필요한 작업이 기하급수적으로 증가함..!(기본값 10)
    }

    @Bean
    public KeyPair keyPair(){
        try {
            var keyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // key size
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex){
            throw new RuntimeException(ex);
        }
    }

    @Bean
    public RSAKey rsaKey(KeyPair keyPair){
        return new RSAKey
                .Builder((RSAPublicKey)keyPair.getPublic()) // 타입 캐스팅 필수
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();// 공개키, 비밀키 설정

    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey){
        var jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        return new NimbusJwtEncoder(jwkSource); // Encoder를 만듦.
    }
    // 공개키와 비밀키가 있는 RSA 키 쌍을 만들고, 인코더와 디코드를 설정했음.
    // SecurityFilterChain이 요청을 인증하게 되고, JWT를 검증하는 역할을 함.
    // REST API에 요청을 전송하려면 먼저 JWT를 만들어야함.

}
