# Security Starter (JWT + OAuth2)

스프링 시큐리티에 JWT와 소셜 로그인을 빠르게 붙일 수 있는 스타터입니다. 의존성 추가 후 설정 몇 줄, 그리고 컨트롤러에서 한 줄 호출만으로 로그인/재발급/소셜 로그인이 동작합니다.

## 제공 기능
- `/auth/login` : username/password JSON 로그인 → Access/Refresh 토큰 발급
- `/auth/refresh` : 리프레시 쿠키로 재발급 (`AuthService.reissue(request, response)` 한 줄)
- `/oauth2/authorization/{registrationId}` : 소셜 로그인(OAuth2) → 성공 시 JWT 발급
- Access 토큰: 헤더, Refresh 토큰: HttpOnly/Secure 쿠키(쿠키 옵션 설정 가능)
- 기본 예외 응답(401/403), 기본 소셜 사용자 매핑(ROLE_USER)

## 빠른 시작
1) 의존성 추가 (Gradle)
```gradle
implementation "com.github.mandoo05:security:1.0.2"
```

2) 필수 설정 (`application.yml`)
```yaml
yh-jwt:
  jwt-secret: <Base64 인코딩된 256비트 키>
  refresh-secret: <Base64 인코딩된 256비트 키>
  cookie-secure: true         # HTTPS 권장
  cookie-same-site: Lax       # None/Strict/Lax
  cookie-domain: ""           # 필요 시 지정
  cookie-path: "/"            # 기본값 "/"
  permit-all: ["/**"]         # 기본 전체 허용 -> 보호는 @PreAuthorize로 제어
```

3) UserDetailsService 구현  
username으로 사용자를 조회할 수 있어야 인증이 동작합니다.

4) (선택) 소셜 로그인 설정  
`spring.security.oauth2.client.registration.google` 등 Spring OAuth2 클라이언트 설정을 추가하면 `/oauth2/authorization/google`로 진입 가능합니다.

5) 사용 예
- 로그인: `POST /auth/login` JSON `{"username":"alice","password":"pw"}` → 헤더 `Authorization: Bearer ...`, 쿠키 `Refresh=...`
- 재발급: `POST /auth/refresh` (리프레시 쿠키 필요) → 새 토큰 세트 발급  
  서비스 코드에서 직접 쓰고 싶다면 `authService.reissue(request, response);` 한 줄.
- 보호된 API: 기본 permitAll이므로 컨트롤러/메서드에 `@PreAuthorize("isAuthenticated()")` 또는 역할 기반 어노테이션을 붙여 보호합니다.

## 코드 예시

### 1) UserDetailsService 간단 구현 (메모리 예시)
```java
@Service
public class SimpleUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) {
        // 실제로는 DB 조회 + 암호화된 비밀번호 사용
        return User.withUsername(username)
                .password("{noop}password") // 데모용, 운영에서는 BCrypt 등 필수
                .roles("USER")
                .build();
    }
}
```

### 2) 컨트롤러 보호하기
```java
@RestController
public class SampleController {
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public String me(Authentication auth) {
        return "hello " + auth.getName();
    }
}
```

### 3) 재발급을 서비스 코드에서 직접 호출
```java
@RestController
@RequiredArgsConstructor
public class TokenController {
    private final AuthService authService;

    @PostMapping("/tokens/reissue")
    public void reissue(HttpServletRequest request, HttpServletResponse response) {
        authService.reissue(request, response);
    }
}
```

### 4) cURL 예시
```bash
# 로그인
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password"}' -i

# 리프레시 (이전에 받은 Refresh 쿠키 사용)
curl -X POST http://localhost:8080/auth/refresh \
  --cookie "Refresh=<refresh-token>" -i

# 보호된 API 호출 (Authorization 헤더에 Access 토큰)
curl http://localhost:8080/me \
  -H "Authorization: Bearer <access-token>"
```

## 클레임과 엔티티 가정
- 기본 JWT 클레임은 `subject`(username)만 포함합니다. JJWT가 `iat`, `exp`를 자동 추가합니다.
- 추가 클레임이 필요하면 `JwtClaimCustomizer` 빈을 등록해 `claims.put("key", value)` 방식으로 넣을 수 있습니다.
- 엔티티/계정 모델은 PK를 `id`, 로그인 식별자를 `username`으로 가정합니다. 다른 필드를 쓰더라도 `UserDetailsService`에서 username에 원하는 값을 매핑하면 됩니다.

## 커스터마이즈 포인트
- 리프레시 저장소: `RefreshTokenStore` 빈 교체 (기본: Stateless). Redis/JPA 구현에서 `save/validate`를 구현하세요.
- 토큰 응답 방식: `TokenResponseWriter` 빈 교체. 헤더/쿠키 조합이나 바디 반환 등 원하는 형태로 작성.
- 쿠키 옵션: `yh-jwt.cookie-*` 프로퍼티로 Secure/SameSite/Domain/Path 설정.
- 허용 경로: `yh-jwt.permit-all`로 시큐리티 체인의 permit 경로 설정.
- 소셜 사용자 매핑: `SocialUserMapper` 빈 교체. 사용자 저장, 권한 부여, 커스텀 username 로직을 추가.
- JWT 프로바이더: 기본은 username을 subject로 사용합니다. 클레임 구조를 바꾸려면 `JwtProvider` 빈을 교체하세요.

## 기본 흐름
1) 로그인 성공 → `SuccessHandler`가 Access/Refresh 토큰 생성, `RefreshTokenStore.save` 호출 후 `TokenResponseWriter`로 응답 작성
2) 요청 진입 → `JwtFilterBasic`이 `Authorization` 헤더를 검증해 `SecurityContext`에 인증 설정(실패 시 401)
3) 재발급 → `AuthService.reissue`가 리프레시 토큰을 검증(`RefreshTokenStore.validate`) 후 새 토큰 발급
4) 소셜 로그인 → `/oauth2/authorization/{id}` → 사용자 정보 조회 후 `SocialUserMapper`로 `YhMemberDetails` 생성 → JWT 발급

## 자주 묻는 질문
- 기본 permitAll인 이유?  
  보안을 컨트롤러/메서드 단의 `@PreAuthorize`로 명시적으로 관리하도록 하기 위함입니다. 필요하면 `permit-all` 프로퍼티로 범위를 좁히세요.
- 키 생성 방법?  
  256비트 랜덤 바이트를 Base64로 인코딩합니다. 예: `openssl rand -base64 32`.
- 테스트는?  
  기본 모듈에는 테스트 소스가 없습니다. 프로젝트 상황에 맞춰 인증/통합 테스트를 추가하세요.
