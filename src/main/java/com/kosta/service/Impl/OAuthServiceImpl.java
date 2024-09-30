package com.kosta.service.Impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.kosta.entity.User;
import com.kosta.repository.UserRepository;
import com.kosta.service.OAuthService;
import com.kosta.util.OAuth2Properties;
import com.kosta.util.TokenUtils;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class OAuthServiceImpl implements OAuthService {
    private final OAuth2Properties oAuth2Properties;
    private final UserRepository userRepository;
    private final TokenUtils tokenUtils;

    @Override
    public String oAuthSignIn(String code, String provider, HttpServletResponse res) {
        // 1. code를 통해 provider에서 제공하는 accessToken 가져온다.
        String providedAccessToken = getAccessToken(code, provider);

        // 2. provider에서 제공하는 accessToken으로 사용자 정보를 추출한다.
        User user = generateOAuthUser(providedAccessToken, provider);

        // 3. 사용자 정보를 조회하고
        // 만약 기존에 있는 사용자라면 (oAuth 인증 여부에 따라 OAUTH True 로 변경)
        // 만약 기존에 없는 사용자라면 (새로 가입 -> DB 추가)
        user = userRepository.findByEmail(user.getEmail()).orElse(user);
        if (user.isOAuth()) {
            user.setOAuth(true);
            userRepository.save(user);
        }

        // 4. 자동 로그인 (사용자에 대한 정보롤 accessToken과 refreshToken을 만들어서 반환)
        Map<String, String> tokenMap = tokenUtils.generateToken(user);

        // DB에 기록하기
        user.setRefreshToken(tokenMap.get("refreshToken"));
        userRepository.save(user);

        // HEADER에 추가
        tokenUtils.setRefreshTokenCookie(res, tokenMap.get("refreshToken"));

        // BODY에 추가
        return tokenMap.get("accessToken");
    }

    // Code를 전달, 사용자 정보 요청
    // {"sub":"102830464863109364648",
    // "name":"Minsung HA",
    // "given_name":"Minsung",
    // "family_name":"HA",
    // "picture":"https://lh3.googleusercontent.com/a/ACg8ocKsuif1zx11QSgpVnO1jmvcfr5STPrCPoEQ3GxXTkiFcAKzWg=s96-c",
    // "email":"codesche@gmail.com","email_verified":true}
    private User generateOAuthUser(String accessToken, String provider) {
        // 설정 가져오기
        OAuth2Properties.Client client = oAuth2Properties.getClients().get(provider);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);

        RestTemplate rt = new RestTemplate();

        // 구글에 저장된 사용자 정보
        ResponseEntity<JsonNode> responseEntity = rt.exchange(client.getUserInfoRequestUri(),
                HttpMethod.GET, new HttpEntity<>(headers), JsonNode.class);

        // response 상태에 따라 구분
        if (!responseEntity.getStatusCode().is2xxSuccessful() || responseEntity.getBody() == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자 정보를 가져올 수 없음");
        }

        JsonNode jsonNode = responseEntity.getBody();
        System.out.println(jsonNode);

        String email = null;
        String name = null;
        User user = null;

        try {
            if (jsonNode.has("email") && jsonNode.has("name")) {
                email = jsonNode.get("email").asText();
                name = jsonNode.get("name").asText();
            } else if (jsonNode.has("id") && jsonNode.has("properties")) {
                email = jsonNode.get("id").asText() + "@kakao.com";
                name = jsonNode.get("properties").get("nickname").asText();
            }
            user = User.builder()
                    .email(email)
                    .name(name)
                    .build();
        } catch (RuntimeException e) {
            throw new RuntimeException("해당 사용자를 찾을 수 없습니다.");
        }
        return user;
    }

    private String getAccessToken(String code, String provider) {
        // 설정 가져오기
        OAuth2Properties.Client client = oAuth2Properties.getClients().get(provider);

        // 1. code를 통해 google에서 제공하는 accessToken 가져온다.
        String decodedCode = URLDecoder.decode(code, StandardCharsets.UTF_8);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(client.getClientId(), client.getClientSecret());

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", client.getClientId());
        params.add("client_secret", client.getClientSecret());
        params.add("code", decodedCode);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", client.getRedirectUri());

        // accessToken 받아오기
        RestTemplate rt = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);
        ResponseEntity<Map> responseEntity = rt.postForEntity(client.getTokenUri(), requestEntity, Map.class);

        // response 상태에 따라 구분
        if (!responseEntity.getStatusCode().is2xxSuccessful() || responseEntity.getBody() == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자 정보를 가져올 수 없음");
        }

        return (String) responseEntity.getBody().get("access_token");
    }

}
