package com.kosta.entity;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

import com.kosta.domain.RoleEnum;
import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@EntityListeners(AuditingEntityListener.class) // 생성, 수정 날짜 추적 -> Application.java (@EnableJpaAuditing)
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User implements UserDetails {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(updatable = false)
	private Long id;
	
	@Column(nullable = false, unique = true)
	private String email;
	
	@Column(nullable = false)
	private String name;

	// 20240919 - not null -> null 로 변경
	@Column(nullable = true)
	private String password;

	// 20240919 - 컬럼 추가
	@Column
	@Builder.Default
	private boolean oAuth = false;
	
	@CreatedDate
	@Column(name = "created_at")
	private LocalDateTime createdAt;
	
	@LastModifiedDate
	@Column(name = "updated_at")
	private LocalDateTime updatedAt;

	@Column(nullable = false)
	@Enumerated(EnumType.STRING)
	@Builder.Default
	private RoleEnum role = RoleEnum.ROLE_USER;			// 권한 컬럼 추가 (기본값 ROLE_USER)

	// 나중에 refresh_token을 저장하도록 변경할 예정
	@Column(name = "refresh_token", nullable = true)
	private String refreshToken;

	// Override - UserDetail
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// 권한 목록 반환
		return List.of(new SimpleGrantedAuthority(role.name()));
	}

	// Override - UserDetail
	@Override
	public String getUsername() {
		// 로그인 할 사용자 명을 이메일로 대체
		return email;
	}
}
