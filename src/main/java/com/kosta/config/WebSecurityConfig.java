package com.kosta.config;

import com.kosta.repository.UserRepository;
import com.kosta.security.*;
import com.kosta.util.TokenUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;

    // JWT Provider
    private JwtProvider jwtProvider() {
        return new JwtProvider(jwtProperties, userDetailsService);
    }

    private TokenUtils tokenUtils() {
        return new TokenUtils(jwtProvider());
    }

    private JwtAuthenticationService jwtAuthenticationService() {
        return new JwtAuthenticationService(tokenUtils(), userRepository);
    }

    @Bean
    // 인증 관리자 (AuthenticationManager) 설정
    AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(bCryptPasswordEncoder());
        return new ProviderManager(authProvider);
    }

    // 암호화 빈
    @Bean
    BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // HTTP 요청에 따른 보안 구성
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 경로 권한 설정
        http.authorizeHttpRequests(auth ->
            // 특정 URL 경로에 대해서는 인증 없이 접근 가능
            auth.requestMatchers(
                new AntPathRequestMatcher("/api/oauth/**"),                 // oAuth 처리 (20240919)
                new AntPathRequestMatcher("/api/auth/signup"),              // 회원가입
                new AntPathRequestMatcher("/api/auth/duplicate"),           // 이메일 중복체크
                new AntPathRequestMatcher("/api/img/**"),                   // 이미지
                new AntPathRequestMatcher("/api/auth/refresh-token"),       // 토큰 재발급
                new AntPathRequestMatcher("/api/post/**", "GET")
            ).permitAll()
            // AuthController 중 나머지들은 "ADMIN"만 가능
            .requestMatchers(
                new AntPathRequestMatcher("/api/auth/")             // "ADMIN"만 가능
            ).hasRole("ADMIN")
            // 그 밖의 다른 요청들은 인증을 통과한(로그인한) 사용자라면 모두 접근할 수 있도록 한다.
            .anyRequest().authenticated()
        );

        // 무상태성 세션 관리
        http.sessionManagement((sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)));

        // 특정 경로(로그인)에 대한 필터 추가
        http.addFilterBefore(new LoginCustomAuthenticationFilter(authenticationManager(), jwtAuthenticationService()),
                UsernamePasswordAuthenticationFilter.class);

        // (토큰을 통해 검증할 수 있도록) 필터 추가
        http.addFilterBefore(new JwtAuthenticationFilter(jwtProvider()),
                UsernamePasswordAuthenticationFilter.class);

        // HTTP 기본 설정
        http.httpBasic(HttpBasicConfigurer::disable);

        // CSRF 비활성화
        http.csrf(AbstractHttpConfigurer::disable);

        // CORS 비활성화 (나중에 변경)
//        http.cors(AbstractHttpConfigurer::disable);

        // CORS 설정
        http.cors(corsConfig -> corsConfig.configurationSource(corsConfigurationSource()));

        return http.getOrBuild();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        return request -> {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedHeaders(Collections.singletonList("*"));
            config.setAllowedMethods(Collections.singletonList("*"));
            config.setAllowedOriginPatterns(Collections.singletonList("http://192.168.233.128"));
            config.setAllowedOrigins(List.of("13.209.80.181", "http://dodream.store", "https://dodream.store"));
            config.setAllowCredentials(true);
            return config;
        };
    }

}
