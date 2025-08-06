## ✅ "Potential OPTIONS Method Request Smuggling Attack: Request Smuggling Detected in Request Body"

| 부분                           | 의미                                         |
| ---------------------------- | ------------------------------------------ |
| **Potential OPTIONS Method** | `OPTIONS` 요청을 사용한 의심스러운 활동                 |
| **Request Smuggling Attack** | HTTP 요청 스머글링 공격 가능성                        |
| **Detected in Request Body** | 요청 \*\*본문(Request Body)\*\*에 의심스러운 형식이 발견됨 |

---

## 🚨 그럼, **HTTP Request Smuggling**이 뭐냐?

### 📌 정의:

> 서버 간 통신에서, **HTTP 요청 파싱의 불일치**를 악용해
> 하나의 요청에 **숨겨진 두 번째 요청**을 몰래 끼워 넣는 공격.

---

## 📦 예를 들어볼게요:

### 1️⃣ 프록시/로드밸런서/웹서버 구조:

```
[Client] → [Proxy] → [Backend Server]
```

### 2️⃣ 요청 스머글링 발생 시:

* 클라이언트가 이상하게 구성된 요청을 보냄

* 프록시는 이렇게 해석:

  ```
  POST / HTTP/1.1
  Content-Length: 30
  ```

  (본문은 30바이트라고 판단)

* 그런데 백엔드는 이렇게 해석:

  ```
  Transfer-Encoding: chunked
  ```

  (본문은 chunked로 해석)

➡️ **서로 다르게 해석되면서** 프록시와 백엔드 간 요청 분리가 꼬이고,
💣 **숨겨진 두 번째 요청이 백엔드에 몰래 전달됨**


## ✅ 취약 여부 판단

공격자가 **스머글링 요청을 보냈을 때**,
서버가 예상치 못한 방식으로 응답하면 → 취약하다고 판단할 수 있어.

---

### 🔥 예시 공격 요청 (Transfer-Encoding과 Content-Length 혼합)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
```

---

## ✅ 그럼 어떤 **응답이 나오면 취약한 걸까?**

### 1. **두 번째 요청이 실제로 처리됨 (Smuggled 요청 처리됨)**

* `OPTIONS`나 `POST`를 보냈는데,
  응답에서 `/admin` 같은 **두 번째 요청의 결과**가 나옴

#### 💥 예: 응답이 이렇다면 위험

```http
HTTP/1.1 200 OK
...
Welcome to admin dashboard!
```

→ 공격자가 **숨긴 GET /admin 요청이 실행됨**
→ 즉, **Request Smuggling 성공 = 취약**

---

### 2. **응답이 꼬임 (잘려 있음, 구조 이상함)**

* 응답이 부분적으로 잘리거나
* 두 응답이 섞여 있음
* 이상한 에러(502, 400, connection close 등)

#### 예:

```http
HTTP/1.1 200 OK
Content-Length: 0

HTTP/1.1 404 Not Found
```

또는

```http
HTTP/1.1 400 Bad Request
Transfer-Encoding error
```

→ 서버 간 요청 파싱 충돌이 발생한 것
→ 이 경우도 취약 가능성 높음

---

### 3. **캐시 오염 (HTTP Desync 공격)**

* 공격자가 숨겨둔 요청을 캐시에 저장시키고,
* 이후 다른 사용자에게 악성 응답이 돌아감

#### 예:

공격자 요청 후:

```http
GET / HTTP/1.1
Host: site.com

0

GET /malicious-content HTTP/1.1
```

→ 이후 일반 사용자가 접속하면
`/malicious-content` 내용이 **정상 페이지처럼 응답됨** → 캐시 오염

---

### ✅ 정리: **이런 응답이 나오면 취약함**

| 응답 패턴                           | 의미                        |
| ------------------------------- | ------------------------- |
| ✅ 숨겨둔 두 번째 요청이 실행됨              | **취약 (완전한 스머글링 성공)**      |
| ⚠️ 응답이 꼬이거나 잘림                  | **취약 가능성 있음**             |
| 🛑 400 / 502 / connection reset | 파싱 충돌 발생, 취약 가능성 있음       |
| 🧪 캐시 결과가 이상하게 바뀜               | 캐시 스머글링 (Desync), 고위험 취약점 |

---

## 💡 이 경우 OPTIONS 메서드가 왜 문제인가?

* 보통 서버는 `OPTIONS` 요청에는 큰 관심을 안 둬요 (검사도 약함)
* 공격자는 이걸 노려서 `OPTIONS` 요청으로 **Request Smuggling을 시도**하기도 함
* 예를 들면, 이런 요청이 들어올 수 있음:

```http
OPTIONS / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
```

* 위 요청은 프록시는 `OPTIONS` 요청으로 보고 끝냄
* 하지만 백엔드는 그 뒤에 숨겨진 `GET /admin` 요청까지 처리해버릴 수 있음

→ 💥 **인증 우회**, **세션 하이재킹**, **캐시 오염**, **XSS, CSRF 삽입** 가능


## 🛡️ 대응 방법 (개발자/보안 담당자용)

| 조치               | 설명                                                                    |
| ---------------- | --------------------------------------------------------------------- |
| ✅ HTTP 표준 일관성 확보 | 프록시, 로드밸런서, 백엔드 모두 동일한 방식(`Content-Length` or `Transfer-Encoding`) 사용 |
| ✅ 혼합 헤더 거부       | `Content-Length`와 `Transfer-Encoding`이 **같이 들어온 요청은 무조건 거부**          |
| ✅ OPTIONS 메서드 제한 | 의심스러운 경로나 바디가 포함된 `OPTIONS` 요청은 거부하거나 로깅                              |
| ✅ 보안 장비 적용       | WAF/IDS/IPS에서 Request Smuggling 패턴 탐지 활성화                             |
| ✅ 최신 보안 패치 적용    | 특히 프록시 서버(Nginx, HAProxy, Apache 등)의 Request Parsing 관련 패치 반영         |

---

### 참고용 링크:

* 🔗 [PortSwigger: HTTP Request Smuggling Labs](https://portswigger.net/web-security/request-smuggling)
* 📘 OWASP 설명: [https://owasp.org/www-community/attacks/HTTP\_Request\_Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)

