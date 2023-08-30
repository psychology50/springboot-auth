# springboot-auth
Spring Security, OAuth2, JWT 등 계정 관리를 위한 커스텀 기능 테스트용

## 추가할 기능
- OAuth2를 연동한 인가 과정
- Spring Security @PreAuthorize 권한 관리

## 작업 사항

<details>
<summary>todos</summary>
<div markdown="1">

- [x] JWT access token 발급
- [x] JWT refresh token 발급
- [x] Redis에 refresh token 저장
- [x] token 유효성 검사
- [x] Redis에서 refresh token 추출
- [x] Secrutiy User 정의 → OAuth2Authentication
- [x] controller까지 인증 과정 테스트
- [ ] aws 환경에 redis 올리기
- [x] access 만료 시, refresh 갱신
- [x] cookie 발급
- [x] 예외 추상화 수준 맞추기
- [x] getGitbubIdtoken → github id 추출
- [x] redis 자체에 만료기간 설정
- [x] token 삭제 메서드 (회원 로그아웃)
- [x] (트레이드 오프) accessToken, refreshToken을 K, V로 했을 때  
      • refreshToken에 아무 값도 저장하지 않아도 됨(만료여부만)  
      • accessToken에서 모든 정보 추출 가능
- [x] token payload 접근자 메서드 공개화 여부 판단
- [ ] JwtTokenProviderImpl 클래스 Thread-safe 체크
- [x] network 작업 exception
- [x] addFilterBefore 순서 확인
- [x] Controller에서 에러났을 때 JwtExceptionFilter에서 처리되는 이유 알아보기
- [x] access와 refresh에 userId, githubId, role 저장
- [x] redisProperties -> yaml에서 주입
- [x] 로그아웃 유저 필터링
- [x] LoginUserIdMethodArgument -> Filter할 거면 나중에 제거
- [x] RoleType 직렬화/역직렬화
- [ ] Filter Test case 작성
- [ ] JwtProvider Test case 작성
- [ ] Redis Test case 작성
- [ ] Cookie Test case 작성
- [x] 프로젝트에 맞게 디렉토리 구조 수정
- [x] refreshToken 정보 추가 -> UUID 대신 generate 메서드 등록
- [x] Enum Converter 적용
- [ ] 로그인 유저 재로그인시 -> 막을 건지, 재발급할 건지
- [x] Redis -> key:value = userId:refreshToken  
      • 같은 pk로 불일치 refresh 요청이 들어온 경우 -> 탈취판단  
      • 해당 userPk 필드 제거 -> 재로그인 요청  
      • 이미 탈취당한 access token은..어쩔 수 없을 듯
- [ ] CustomUserDetails Deserializer를 위해 필드 조정

</div>
</details>

### 📌 주요 모듈 (팀원이 사용하게 된다면 이것들)
1️⃣ **JwtTokenProvider**
```java
public interface JwtTokenProvider {
    /**
     * 헤더로부터 토큰을 추출하고 유효성을 검사하는 메서드
     * @param authHeader : 메시지 헤더
     * @return String : 토큰
     * @throws AuthErrorException : 토큰이 유효하지 않을 경우
     */
    String resolveToken(String authHeader) throws AuthErrorException;

    /**
     * 사용자 정보 기반으로 액세스 토큰을 생성하는 메서드
     * @param user UserDto : 사용자 정보
     * @return String : 토큰
     */
    String generateAccessToken(JwtUserInfo user);

    /**
     * 사용자 정보 기반으로 리프레시 토큰을 생성하는 메서드
     * @param user UserDto : 사용자 정보
     * @return String : 토큰
     */
    String generateRefreshToken(JwtUserInfo user);

    /**
     * token으로 부터 사용자 정보를 추출하는 메서드
     * @param token String : 토큰
     * @return UserAuthenticateReq : 사용자 정보
     * @throws AuthErrorException : 토큰이 유효하지 않을 경우
     */
    JwtUserInfo getUserInfoFromToken(String token) throws AuthErrorException;

    /**
     * 토큰으로 부터 유저 아이디를 추출하는 메서드
     * @param token String : 토큰
     * @return Long : 유저 아이디
     * @throws AuthErrorException : 토큰이 유효하지 않을 경우
     */
    Long getUserIdFromToken(String token) throws AuthErrorException;

    /**
     * 토큰의 만료일을 추출하는 메서드
     * @param token String : 토큰
     * @return Date : 만료일
     * @throws AuthErrorException : 토큰이 유효하지 않을 경우
     */
    Date getExpiryDate(String token) throws AuthErrorException;
}
```
- 토큰을 발급하고, 토큰의 유효성을 검사하는 메서드를 제공합니다.
- userId를 제외하고는 모두 JwtUserInfo 객체를 통해 토큰을 생성합니다.  
  - JwtUserInfo : userId, githubId, role을 가지고 있습니다.
- 어차피 Authentication으로 로그인 유저 정보를 가져올 수 있으므로, githubId와 role 접근자 메서드는 제외하였습니다.
- 특별한 사유가 없다면 `Service 계층`에서 사용하도록 설계하였습니다.

<br/>

2️⃣ **CookieUtil**
```java
@Component
public class CookieUtil {
    /**
     * request에서 cookieName에 해당하는 쿠키를 찾아서 반환합니다.
     * @param request HttpServletRequest : 쿠키를 찾을 request
     * @param cookieName String : 찾을 쿠키의 이름
     * @return Optional<Cookie> : 쿠키가 존재하면 해당 쿠키를, 존재하지 않으면 Optional.empty()를 반환합니다.
     */
    public Optional<Cookie> getCookie(HttpServletRequest request, String cookieName);

    /**
     * cookieName에 해당하는 쿠키를 생성합니다.
     * @param cookieName String : 생성할 쿠키의 이름
     * @param value String : 생성할 쿠키의 값
     * @param maxAge int : 생성할 쿠키의 만료 시간
     * @return ResponseCookie : 생성된 쿠키
     */
    public ResponseCookie createCookie(String cookieName, String value, int maxAge);

    /**
     * cookieName에 해당하는 쿠키를 제거합니다.
     * @param request HttpServletRequest : 쿠키를 제거할 request
     * @param response HttpServletResponse : 쿠키를 제거할 response
     * @param cookieName String : 제거할 쿠키의 이름
     * @return Optional<ResponseCookie> : 쿠키가 존재하면 제거된 쿠키를, 존재하지 않으면 Optional.empty()를 반환합니다.
     */
    public Optional<ResponseCookie> deleteCookie(HttpServletRequest request, HttpServletResponse response, String cookieName);
}
```
- 쿠키를 생성하고, 쿠키를 제거하는 메서드를 제공합니다.
- 특별한 사유가 없다면, `Controller`계층에서 사용하도록 설계하였습니다.

<br/>

3️⃣ **RefreshTokenService**
```java
public interface RefreshTokenService {
    /**
     * access token을 받아서 refresh token을 발행
     * @param accessToken : JwtUserInfo
     * @return String : Refresh Token
     * @throws AuthErrorException : 토큰이 유효하지 않을 경우
     */
    String issueRefreshToken(String accessToken) throws AuthErrorException;

    /**
     * refresh token을 받아서 refresh token을 재발행
     * @param requestRefreshToken : String
     * @return RefreshToken
     * @throws AuthErrorException : 토큰이 유효하지 않을 경우(REFRESH_TOKEN_EXPIRED), 토큰이 탈취당한 경우(REFRESH_TOKEN_MISMATCH)
     */
    RefreshToken refresh(String requestRefreshToken) throws AuthErrorException;

    /**
     * access token 으로 refresh token을 찾아서 제거 (로그아웃)
     * @param requestRefreshToken : String
     */
    void logout(String requestRefreshToken);
}
```
- refresh token 발급, 재발급, 제거 메서드를 제공합니다.
- RTR(Refresh Token Rotation) 방식을 통해 보안성을 높였습니다.
    - redis에선 refresh token을 key:value=userId:refreshToken으로 저장합니다.
    - refresh token으로 access token을 재발급 받으면, refresh token도 재발급됩니다.
    - 재발급된 refresh token 유효기간은 연장되지 않습니다. (기본 7일)
    - refresh token이 탈취된 경우(특정 userId로 잘못된 refresh token이 요청된 경우) 해당 userId의 refresh token은 모두 삭제되며, 해당 userId로 재로그인을 요청해야 합니다.
    - 탈취된 refresh token으로 이미 재발급된 access token에 대해서는 어쩔 수 없이 유효기간이 만료될 때까지 기다려야 합니다. (현재로썬 보완할 방도를 찾지 못했습니다.)
- 특별한 사유가 없다면, `Service 계층`에서 사용하도록 설계하였습니다.

<br/>

4️⃣ **ForbiddenTokenService**
```java
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@Component
public class ForbiddenTokenService {
    private final ForbiddenTokenRepository forbiddenTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 토큰을 블랙 리스트에 등록합니다.
     * @param accessToken : 블랙 리스트에 등록할 토큰
     * @param userId : 블랙 리스트에 등록할 사용자 ID
     */
    public void register(String accessToken, Long userId);

    /**
     * 토큰이 블랙 리스트에 등록되어 있는지 확인합니다.
     * @param accessToken : 확인할 토큰
     * @return : 블랙 리스트에 등록되어 있으면 true, 아니면 false
     */
    public boolean isForbidden(String accessToken);
}
```
- 토큰을 블랙 리스트에 등록하고, 토큰이 블랙 리스트에 등록되어 있는지 확인하는 메서드를 제공합니다.
- 특별한 사유가 없다면, `Service 계층`에서 사용하도록 설계하였습니다.

<br/>

### 📌 유즈 케이스  
> 아래 순서를 따르지 않을 시, 정상 작동 여부를 보장하지 않습니다.

<br/>

1️⃣ **로그인**  
🟡 *Controller*  
```java
@PostMapping("/login")
public ResponseEntity<?> loginTest(@RequestBody UserAuthReq dto) {
    Map<String, String> tokens = userAuthService.login(dto); // 로그인 유저 정보로 accessToken, refreshToken 발급
    ResponseCookie cookie = cookieUtil.createCookie(REFRESH_TOKEN.getValue(), tokens.get(REFRESH_TOKEN.getValue()), 60 * 60 * 24 * 7); // refreshToken 쿠키 생성

    return ResponseEntity.noContent()
            .header(HttpHeaders.SET_COOKIE, cookie.toString()) // refreshToken 쿠키를 response header에 추가
            .header(ACCESS_TOKEN.getValue(), tokens.get(ACCESS_TOKEN.getValue())) // accessToken을 response header에 추가
            .build();
}
```


<br/>

🟡 *Service*    
```java
public Map<String, String> login(UserAuthReq dto) {
    User user = userSearchService.findById(dto.getId()); // 로그인 유저 정보 조회
    JwtUserInfo jwtUserInfo = JwtUserInfo.from(user); // 로그인 유저 정보로 JwtUserInfo 객체 생성

    String accessToken = jwtTokenProvider.generateAccessToken(jwtUserInfo); // accessToken 발급
    String refreshToken = refreshTokenService.issueRefreshToken(accessToken); // refreshToken 발급

    return Map.of(ACCESS_TOKEN.getValue(), accessToken, REFRESH_TOKEN.getValue(), refreshToken); // accessToken, refreshToken 반환
}
```

<br/>

2️⃣ **로그아웃**  
🟡 *Controller*  
```java
@GetMapping("/logout")
public ResponseEntity<?> logoutTest(@CookieValue("refreshToken") String refreshToken, HttpServletRequest request, HttpServletResponse response) {
    userAuthService.logout(request.getHeader(AUTH_HEADER.getValue()), refreshToken); // 로그아웃을 위해 accessToken, refreshToken 모두 필요
    ResponseCookie cookie = cookieUtil.deleteCookie(request, response, REFRESH_TOKEN.getValue()) // refreshToken 쿠키 제거
            .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 쿠키입니다.")); // TODO : 공통 예외로 변경

    return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookie.toString()).build(); // 값이 비어있는 쿠키를 response header에 추가
}
```

<br/>

🟡 *Service*    
```java
public void logout(String authHeader, String requestRefreshToken) {
    String accessToken = jwtTokenProvider.resolveToken(authHeader); // 헤더로부터 accessToken 추출
    Long userId = jwtTokenProvider.getUserIdFromToken(accessToken); // accessToken으로 userId 추출

    refreshTokenService.logout(requestRefreshToken); // redis에서 refreshToken 제거
    forbiddenTokenService.register(accessToken, userId); // accessToken을 블랙 리스트에 등록 (남아있는 유효 시간만큼)
}
```

<br/>

3️⃣ **refreshToken 재발급**  
🟡 *Controller*  
```java
@GetMapping("/refresh")
public ResponseEntity<?> refreshTest(@CookieValue("refreshToken") String refreshToken) {
    if (refreshToken == null) {
        throw new IllegalArgumentException("존재하지 않는 쿠키입니다."); // TODO : 공통 예외로 변경
    }
    Map<String, String> tokens = userAuthService.refresh(refreshToken); // refreshToken으로 accessToken, refreshToken 재발급
    ResponseCookie cookie = cookieUtil.createCookie(REFRESH_TOKEN.getValue(), tokens.get(REFRESH_TOKEN.getValue()), 60 * 60 * 24 * 7); // refreshToken 쿠키 생성 
    // 클라이언트 측에 쿠키가 남아 있어도 서버 측에서 만료되면 사라질 것이므로 쿠키의 만료 시간은 7일로 고정해도 무방합니다.

    return ResponseEntity.noContent()
            .header(HttpHeaders.SET_COOKIE, cookie.toString()) // refreshToken 쿠키를 response header에 추가
            .header(ACCESS_TOKEN.getValue(), tokens.get(ACCESS_TOKEN.getValue())) // accessToken을 response header에 추가
            .build();
}
```


<br/>

🟡 *Service*    
```java
public Map<String, String> refresh(String requestRefreshToken) {
    RefreshToken refreshToken = refreshTokenService.refresh(requestRefreshToken); // refreshToken으로 새로 발급한 RefreshToken 객체 반환 (refreshToken가 탈취되었다면 예외 발생)

    Long userId = refreshToken.getUserId(); // userId 추출
    JwtUserInfo dto = JwtUserInfo.from(userSearchService.findById(userId)); // userId로 JwtUserInfo 객체 생성
    String accessToken = jwtTokenProvider.generateAccessToken(dto); // accessToken 재발급

    return Map.of(ACCESS_TOKEN.getValue(), accessToken, REFRESH_TOKEN.getValue(), refreshToken.getToken()); // accessToken, refreshToken 반환
}
```


<br/>

4️⃣ **Authentication 객체 받기**
```java
@GetMapping("/authentication")
public ResponseEntity<?> authenticationTest(@AuthenticationPrincipal CustomUserDetails securityUser, Authentication authentication) {
    log.info("type: {}", authentication.getPrincipal()); // io.oopy.coding.common.security.CustomUserDetails
    JwtUserInfo user = securityUser.toJwtUserInfo();
    log.info("user: {}", user); // user: JwtUserInfo(id=2, githubId=0, role=ROLE_ADMIN)

    return ResponseEntity.ok(user);
}
```
- Authentication으로 받고 authentication.getPrincipal() : CustomUserDetails
- 혹은, @AuthenticationPrincipal로 받고 securityUser.toJwtUserInfo() : JwtUserInfo

<br/>

### 📌 Authentication Filter 로직
1️⃣ **Exception Handler**  

<div align="center" markdown="1">

![image](https://github.com/80000Coding/80000Coding-Backend/assets/96044622/3ddf2830-3148-4ef1-b672-38f72aa48260)

</div>


<br/>

🟡 *JwtExceptionFilter*

<div align="center" markdown="1">

![image](https://github.com/psychology50/trip-tip/assets/96044622/9b47b85e-cd08-4c16-83f7-bd33e832793c)

</div>

- AuthErrorException을 상속받은 에러들을 처리합니다.
- AuthErrorException에 대해서는 언제나 같은 에러 포맷으로 응답합니다.
- AuthErrorException으로 처리되지 않은 에러에 대해서는 500 INTERNAL_SERVER_ERROR로 응답합니다.  

<br/>

🟡 *AccessDeniedHandler*

<div align="center" markdown="1">

![image](https://github.com/psychology50/algorithm-strategies/assets/96044622/5d1156b3-eab6-4aeb-8f8e-10a5af4827a7)

</div>

```java
/**
 * 유저 정보는 있으나 자원에 접근할 수 있는 권한이 없는 경우 : 403 Forbidden
 */
@Component
@Slf4j
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.error("handle error: {}", accessDeniedException.getMessage());
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}
```
- 인증은 됐으나 인가될 수 없는 자원에 접근할 때 403 Forbidden으로 응답합니다.
- hasRole() : 특정 권한을 가지고 있는지 확인합니다.
- hasAnyRole() : 여러 권한 중 하나라도 가지고 있는지 확인합니다.
- hasAuthority() : 특정 권한을 가지고 있는지 확인합니다.
- hasAnyAuthority() : 여러 권한 중 하나라도 가지고 있는지 확인합니다.
- hasIpAddress() : 특정 IP 주소를 가지고 있는지 확인합니다.
- access() : SpEL 표현식을 이용해서 권한을 확인합니다.
- permitAll() : 모든 사용자가 접근할 수 있습니다.
- denyAll() : 모든 사용자의 접근을 거부합니다.
- anonymous() : 익명 사용자만 접근할 수 있습니다.
- rememberMe() : remember-me로 인증된 사용자만 접근할 수 있습니다.
- authenticated() : 인증된 사용자만 접근할 수 있습니다.

<br/>

🟡 *AuthenticationEntryPoint*
```java
/**
 * 유저 정보가 없는 경우 : 401 Unauthorized
 */
@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.error("commence error: {}", authException.getMessage());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
```
- 인증이 안 된 사용자가 자원에 접근하려 할 때 401 Unauthorized으로 응답합니다.

<br/>

2️⃣ **AuthErrorCode**
```java
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public enum AuthErrorCode implements ErrorCode {
    // 400 BAD_REQUEST: 클라이언트의 요청이 부적절 할 경우
    INVALID_HEADER(BAD_REQUEST, "유효하지 않은 헤더 포맷입니다"),
    EMPTY_ACCESS_TOKEN(BAD_REQUEST, "토큰이 비어있습니다"),

    // 401 UNAUTHORIZED: 인증되지 않은 사용자
    TAMPERED_ACCESS_TOKEN(UNAUTHORIZED, "서명이 조작된 토큰입니다"),
    EXPIRED_ACCESS_TOKEN(UNAUTHORIZED, "사용기간이 만료된 토큰입니다"),
    MALFORMED_ACCESS_TOKEN(UNAUTHORIZED, "비정상적인 토큰입니다"),
    WRONG_JWT_TOKEN(UNAUTHORIZED, "잘못된 토큰입니다(default)"),
    REFRESH_TOKEN_NOT_FOUND(UNAUTHORIZED, "없거나 삭제된 리프래시 토큰입니다."),
    USER_NOT_FOUND(UNAUTHORIZED, "존재하지 않는 유저입니다"),

    // 403 FORBIDDEN: 인증된 클라이언트가 권한이 없는 자원에 접근
    FORBIDDEN_ACCESS_TOKEN(FORBIDDEN, "해당 토큰에는 엑세스 권한이 없습니다"),
    MISMATCHED_REFRESH_TOKEN(FORBIDDEN, "리프레시 토큰의 유저 정보가 일치하지 않습니다");

    private final HttpStatus httpStatus;
    private final String message;

    @Override public String getMessage() {
        return this.message;
    }

    @Override public String getName() {
        return this.name();
    }
}
```
JwtExceptionFilter에서 처리하는 에러 응답 포맷은 다음과 같습니다.
```json
// status : 400 BAD_REQUEST
{
    "code": "INVALID_HEADER",
    "message": "유효하지 않은 헤더 포맷입니다",
}
```

<br/>

### 📌 서브 기능 및 클래스
1️⃣ **JwtUserInfo**
```java
@Builder
public record JwtUserInfo(
        Long id,
        Integer githubId,
        RoleType role
) {
    public static JwtUserInfo of(Long id, Integer githubId, RoleType role) {
        return new JwtUserInfo(id, githubId, role);
    }

    public static JwtUserInfo from(User user) {
        return new JwtUserInfo(user.getId(), user.getGithubId(), user.getRole());
    }

    @Override public String toString() {
        return String.format("JwtUserInfo(id=%d, githubId=%d, role=%s)", id, githubId, role);
    }
}
```
- userId, githubId, role을 가지고 있습니다.
- jwt util에서 사용하기 위한 record입니다.

<br/>

2️⃣ **Cache**
```java
@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    @Cacheable(value = "securityUser", key = "#userId", unless = "#result == null")
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        log.debug("loadUserByUsername userId : {}", userId);
        return userRepository.findById(Long.parseLong(userId))
                .map(CustomUserDetails::of)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }
}
```
- userId를 key로 하여 CustomUserDetails를 캐싱합니다.
- 캐싱된 CustomUserDetails는 30초 동안 유지됩니다.

<br/>

3️⃣ **여러가지 enum 클래스**  
🟡 *RoleType*
```java
@RequiredArgsConstructor
public enum RoleType implements LegacyCommonType {
    ADMIN("1", "ROLE_ADMIN"),
    USER("2", "ROLE_USER");

    private final String code;
    private final String role;
    private static final Map<String, RoleType> stringToEnum =
            Stream.of(values()).collect(toMap(Object::toString, e -> e));

    @JsonValue
    public String getRole() { return role; }
    @Override
    public String getCode() { return code; }

    @JsonCreator
    public static RoleType fromString(String role) {
        return stringToEnum.get(role.toUpperCase());
    }

    @Override public String toString() { return role; }
}
```
- 유저의 권한을 정의합니다.
- Spring Application에서는 role 이름을 사용하고, DB에는 code를 저장합니다.

<br/>

🟡 *AuthConstants*
```java
@Getter
public enum AuthConstants {
    AUTH_HEADER("Authorization"), TOKEN_TYPE("Bearer "),
    ACCESS_TOKEN("accessToken"), REFRESH_TOKEN("refreshToken");

    private String value;

    AuthConstants(String value) {
        this.value = value;
    }

    @Override public String toString() {
        return String.format("AuthConstants(value=%s)", this.value);
    }
}

```
- 헤더에 담길 토큰의 키, 토큰의 타입, 토큰의 이름을 정의합니다.

<br/>

4️⃣ *Converter Util*  
사용 방법만 아셔도 됩니다.  
상세한 로직이 궁금하신 분들은 마지막에 토글바 열어보시면 됩니다.  

<br/>

🟡 *Enum 타입 클래스*  
```java
@RequiredArgsConstructor
public enum RoleType implements LegacyCommonType {
    ADMIN("1", "ROLE_ADMIN"),
    USER("2", "ROLE_USER");

    private final String code;
    private final String role;
    
    ...

    @Override
    public String getCode() { return code; }

    ...
}
```
- DB에 저장되는 값은 code입니다. (DB 공간 절약)
- DB 조회 시, code를 role로 변환하여 반환합니다.
- (해당 방식을 적용할)Enum 타입 클래스는 반드시 LegacyCommonType 인터페이스를 상속받아야 합니다.

<br/>

🟡 *해당 Enum 타입 클래스 Converter 정의*  
```java
@Convert
public class RoleTypeConverter extends AbstractLegacyEnumAttributeConverter<RoleType> {
    private static final String ENUM_NAME = "유저권한";

    public RoleTypeConverter() {
        super(RoleType.class, false, ENUM_NAME);
    }
}
```
- AbstractLegacyEnumAttributeConverter를 상속받아 구현합니다.
- AbstractLegacyEnumAttributeConverter의 생성자에는 Enum 타입 클래스, nullable 여부, Enum 타입 클래스의 설명적 이름을 전달합니다.
    - 설명적 이름은 예외 발생 시, 예외 메시지에 사용됩니다.
    - nullable이 false이면, 변환할 값이 null로 들어왔을 때 예외를 발생시킵니다.
- AbstractLegacyEnumAttributeConverter를 상속받은 클래스는 반드시 @Convert 어노테이션을 붙여야 합니다.

<br/>

🟡 *필드 정의*  
```java
@Convert(converter = RoleTypeConverter.class)
@Column(name = "role", nullable = false)
private RoleType role;
```
- @Convert 어노테이션에는 해당 Enum 타입 클래스 Converter를 전달합니다.

<br/>

<details>
<summary>구현 내용</summary>
<div markdown="1">

🟡 *Enum Class에서 상속받는 LegacyCommonType 인터페이스*  
```java
public interface LegacyCommonType {
    /**
     * Legacy Super System 공통 코드를 반환한다.
     * @return String 공통 코드
     */
    String getCode();
}
```
- DB에 저장되어야 할 code를 반환하는 메서드를 정의합니다.

<br/>

🟡 *enum↔String 상호변환 LegacyEnumValueConvertUtils*  
```java
/**
 * {@link LegacyCommonType} enum을 String과 상호 변환하는 유틸리티 클래스
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class LegacyEnumValueConvertUtils {
    public static <T extends Enum<T> & LegacyCommonType> T ofLegacyCode(Class<T> enumClass, String code) {
        if (!StringUtils.hasText(code)) return null;
        return EnumSet.allOf(enumClass).stream()
                .filter(e -> e.getCode().equals(code))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        String.format("enum=[%s], code=[%s]가 존재하지 않습니다.", enumClass.getName(), code))); // TODO : 공통 예외로 변경
    }

    public static <T extends Enum<T> & LegacyCommonType> String toLegacyCode(T enumValue) {
        if (enumValue == null) return "";
        return enumValue.getCode();
    }
}
```
- enum↔String 상호변환을 위한 유틸리티 클래스입니다.
- enum↔String 상호변환을 위한 메서드는 다음과 같습니다.
    - `ofLegacyCode(Class<T> enumClass, String code)` : code를 전달받아 enum으로 변환합니다.
    - `toLegacyCode(T enumValue)` : enum을 전달받아 code로 변환합니다.
- 반드시 `LegacyCommonType` 인터페이스를 상속받은 enum 타입 클래스를 전달받아야 합니다.

<br/>

🟡 *AttributeConverter 구현 클래스*  
```java
@Getter
public class AbstractLegacyEnumAttributeConverter<E extends Enum<E> & LegacyCommonType> implements AttributeConverter<E, String> {
    /**
     * 대상 Enum 클래스 {@link Class} 객체
     */
    private final Class<E> targetEnumClass;

    /**
     * <code>nullable = false</code>면, 변환할 값이 null로 들어왔을 때 예외를 발생시킨다.<br/>
     * <code>nullable = true</code>면, 변환할 값이 null로 들어왔을 때 예외 없이 실행하며,<br/>
     * legacy code로 변환 시엔 빈 문자열("")로 변환한다.
     */
    private final boolean nullable;

    /**
     * <code>nullable = false</code>일 때 출력할 오류 메시지에서 enum에 대한 설명을 위해 Enum의 설명적 이름을 받는다.
     */
    private final String enumName;

    public AbstractLegacyEnumAttributeConverter(Class<E> targetEnumClass, boolean nullable, String enumName) {
        this.targetEnumClass = targetEnumClass;
        this.nullable = nullable;
        this.enumName = enumName;
    }

    @Override
    public String convertToDatabaseColumn(E attribute) {
        if (!nullable && attribute == null) {
            throw new IllegalArgumentException(String.format("%s을(를) null로 변환할 수 없습니다.", enumName));
        }
        return LegacyEnumValueConvertUtils.toLegacyCode(attribute);
    }

    @Override
    public E convertToEntityAttribute(String dbData) {
        if (!nullable && !StringUtils.hasText(dbData)) {
            throw new IllegalArgumentException(String.format("%s(이)가 DB에 null 혹은 Empty로(%s) 저장되어 있습니다.", enumName, dbData));
        }
        return LegacyEnumValueConvertUtils.ofLegacyCode(targetEnumClass, dbData);
    }
}
```
- AttributeConverter를 상속받아 구현합니다.

</div>
</details>


<br/>

### 📌 추가 고려 사항
- 디렉토리 구조 어떻게 해야 더 깔끔할 지 고민 중
- CustomUserDetails Deserializer 이슈 -> 역직렬화 안 되는 거 전부 `@JsonIgnore` 처리해버림..^^
