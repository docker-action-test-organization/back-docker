package com.kosta.service.Impl;

import java.util.List;
import java.util.Map;

import com.kosta.domain.request.SignUpRequest;
import com.kosta.domain.request.UserDeleteRequest;
import com.kosta.domain.request.UserUpdateRequest;
import com.kosta.domain.response.UserResponse;
import com.kosta.security.JwtProvider;
import com.kosta.service.AuthService;
import com.kosta.util.TokenUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.kosta.entity.User;
import com.kosta.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final JwtProvider jwtProvider;
	private final TokenUtils tokenUtils;

	@Override
	public UserResponse signUp(SignUpRequest signUpRequest) {
		String encodedPassword = bCryptPasswordEncoder.encode(signUpRequest.getPassword());

		User user = User.builder()
				.email(signUpRequest.getEmail())
				.name(signUpRequest.getName())
				.password(encodedPassword)
				.build();

		User savedUser = userRepository.save(user);
		return UserResponse.toDTO(savedUser);
	}

	@Override
	public List<UserResponse> getUserList() {
		List<User> userList = userRepository.findAll();
		return userList.stream().map(UserResponse::toDTO).toList();
	}

	@Override
	public UserResponse updateUser(UserUpdateRequest userUpdateRequest) {
		User user = userRepository.findByEmail(userUpdateRequest.getEmail())
				.orElseThrow(() -> new IllegalArgumentException("회원 정보 조회에 실패했습니다. [없는 이메일]"));
		boolean isMatch = bCryptPasswordEncoder.matches(userUpdateRequest.getPassword(), user.getPassword());

		if (!isMatch) {
			throw new RuntimeException("비밀번호 입력 오류");
		}

		if (userUpdateRequest.getName() != null) {
			user.setName(userUpdateRequest.getName());
		}

		User updatedUser = userRepository.save(user);
		return UserResponse.toDTO(updatedUser);
	}

	@Override
	public void deleteUser(UserDeleteRequest userDeleteRequest) {
		User user = userRepository.findByEmail(userDeleteRequest.getEmail())
				.orElseThrow(() -> new IllegalArgumentException("회원 정보 조회에 실패했습니다. [없는 이메일]"));
		boolean isMatch = bCryptPasswordEncoder.matches(userDeleteRequest.getPassword(), user.getPassword());

		if (!isMatch) {
			throw new RuntimeException("비밀번호 입력 오류");
		}
			
		userRepository.delete(user);
	}

	@Override
	public boolean duplicateCheckEmail(String email) {
		return !userRepository.existsByEmail(email);
	}

	private String extractRefreshTokenFromCookie(HttpServletRequest req) {
		Cookie[] cookies = req.getCookies();
		if (cookies != null) {
			for (Cookie c : cookies) {
				if (c.getName().equals("refreshToken")) {
					return c.getValue();
				}
			}
		}
		return null;
	}

	@Override
	public Map<String, String> refreshToken(HttpServletRequest request) {
		// 쿠키에서 RefreshToken 추출
		String refreshToken = extractRefreshTokenFromCookie(request);

		// 만약 토큰이 유효하지 않으면 null
		if (refreshToken == null || !jwtProvider.validToken(refreshToken)) {
			return null;
		}

		// 유효한 토큰에서 이메일 추출
		String userEmail = jwtProvider.getUserEmailByToken(refreshToken);
		log.info("추출한 이메일 : {} ", userEmail);

		// 이메일을 통한 사용자 조회 후, refreshToken 비교
		User user = userRepository.findByEmail(userEmail).orElse(null);
		if (user == null || !user.getRefreshToken().equals(refreshToken)) {
			return null;
		}

		// 새로운 토큰 생성 후, DB에 refreshToken 저장
		Map<String, String> tokenMap = tokenUtils.generateToken(user);
		user.setRefreshToken(tokenMap.get("refreshToken"));
		userRepository.save(user);

		return tokenMap;
	}

//	@Override
//	public LoginResponse login(String email, String password) {
//		User user = userRepository.findByEmail(email)
//				.orElseThrow(() -> new IllegalArgumentException("없는 이메일"));
//		// bCryptPasswordEncoder.matches(원문, 평문);
//		boolean matchedPassword = bCryptPasswordEncoder.matches(password, user.getPassword());
//
//		if (!matchedPassword) {
//			throw new RuntimeException("비밀번호 불일치");
//		}
//
//		String accessToken = jwtProvider.generateAccessToken(user);
//
//		return LoginResponse.builder()
//				.accessToken(accessToken).build();
//	}
}
