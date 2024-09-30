package com.kosta.security;

import com.kosta.domain.response.LoginResponse;
import com.kosta.entity.User;
import com.kosta.repository.UserRepository;
import com.kosta.util.TokenUtils;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwtAuthenticationService {

    private final TokenUtils tokenUtils;
    private final UserRepository userRepository;

    void successAuthentication(HttpServletResponse response, Authentication authResult) throws IOException {
        User user = (User) authResult.getPrincipal();
        Map<String, String> tokenMap = tokenUtils.generateToken(user);
        String accessToken = tokenMap.get("accessToken");                   // 액세스 토큰 가져오기
        String refreshToken = tokenMap.get("refreshToken");                 // 리프레시 토큰 가져오기

        // 리프레시 토큰을 DB에 저장!
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        tokenUtils.setRefreshTokenCookie(response, refreshToken);

        LoginResponse loginResponse = LoginResponse.builder()
                    .accessToken(accessToken)
                    .build();
        tokenUtils.writeResponse(response, loginResponse);
    }

}
