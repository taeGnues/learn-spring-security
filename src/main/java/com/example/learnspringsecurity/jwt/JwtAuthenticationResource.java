package com.example.learnspringsecurity.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;

import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
//@RestController
public class JwtAuthenticationResource {

    private JwtEncoder jwtEncoder;
    // 2. Jwt token을 만들려면 Jwt Encoder가 필요함

    @Autowired
    public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    } // 생성자 주입

    @PostMapping("/authenticate")
    public JwtRespose authenticate(Authentication authentication) {
        // 1. 이곳으로 basic authentication 요청을 전송하고 인증 세부 정보를 받음!
        return new JwtRespose(createToken(authentication));
        // authentication을 받아서 그것으로 Jwt token을 만듦
    }

    private String createToken(Authentication authentication) {
        var claims = JwtClaimsSet
                .builder()
                .issuer("self") // 토큰 발행자
                .issuedAt(Instant.now()) // 토큰 발행일
                .expiresAt(Instant.now().plusSeconds(60 * 30)) // 토큰 만료일, 30분
                .subject(authentication.getName()) // 토큰 주제
                .claim("scope", createScope(authentication)) // 갖고 있는 권한 범위
                .build();
        // JwtClaimsSet : Json web token이 전달한 클레임을 나타내는 json 객체



        return jwtEncoder.encode(JwtEncoderParameters.from(claims))
                .getTokenValue();

        // claim으로부터 JwtEncoderParameters를 만들고,
        // 그걸 encoding하고 getTokenValue()를 해서 토큰값을 리턴함
    }

    private String createScope(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(a -> a.getAuthority()) // authorities에 대해 문자열로 된 리스트를 갖음.
                .collect(Collectors.joining(" "));
        // 리스트의 원소 10개가 있다면 그것들이 모두 수집돼 결합됨. 공백으로 구분됨.
    }
}

record JwtRespose(String token) {}