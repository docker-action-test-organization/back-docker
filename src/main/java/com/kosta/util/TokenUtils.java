package com.kosta.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kosta.domain.response.LoginResponse;
import com.kosta.entity.User;
import com.kosta.security.JwtProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class TokenUtils {

    private final JwtProvider jwtProvider;

    // 토큰 생성
    public Map<String, String> generateToken(User user) {
        String accessToken = jwtProvider.generateAccessToken(user);
        String refreshToken = jwtProvider.generateRefreshToken(user);

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", accessToken);
        tokenMap.put("refreshToken", refreshToken);
        return tokenMap;
    }

    // JSON 응답 전송
    public void writeResponse(HttpServletResponse response, LoginResponse loginResponse) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(loginResponse);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(jsonResponse);
    }

    public void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);               // JavaScript에서 변경 불가
        refreshTokenCookie.setSecure(false);                // HTTPS가 아니어도 사용 가능!!! (실제는 true로 해줘야 함!)
        refreshTokenCookie.setPath("/");                    // 다 쓰인다
        refreshTokenCookie.setMaxAge(1 * 24 * 60 * 60);     // Token 유효기간 1일
        response.addCookie(refreshTokenCookie);
    }
}
