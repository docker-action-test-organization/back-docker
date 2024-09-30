package com.kosta.controller;

import com.kosta.domain.response.LoginResponse;
import com.kosta.service.OAuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
@RequestMapping("/api/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuthService oAuthService;

    // 구글 로그인 기능 - code 전달
    @GetMapping("/{provider}")
    public ResponseEntity<?> socialSignIn(@RequestParam("code") final String code,
                                          @PathVariable("provider") final String provider,
                                        HttpServletResponse res) {
        log.info("들어온 코드 값 : {}", code);
        String accessToken = oAuthService.oAuthSignIn(code, provider, res);

        // code를 통해 사용자 정보를 받아서
        // 사용자 정보를 조회하고, 만약 기존에 있는 사용자라면 (oauth 값을 true 로 변경)
        // 만약 기존에 없는 사용자라면 (새로 가입 -> DB 추가)
        // 사용자에 대한 정보롤 accessToken과 refreshToken을 만들어서 반환

        if (accessToken == null || accessToken.equals("")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        LoginResponse loginResponse = LoginResponse.builder()
                                                .accessToken(accessToken)
                                                .build();
        return ResponseEntity.ok(loginResponse);
    }

}
