DNS DNSSEC

-
HTTP Strict-Transport-Security (HSTS)
-
Strict-Transport-Security
-
Content-Security-Policy
-
Referrer-Policy

---
## 🧱 브라우저 보안 헤더 4종 세트


```http
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=UTF-8
Content-Security-Policy: default-src 'self'
X-Frame-Options: SAMEORIGIN
```

---
## 🧩 `X-Content-Type-Options` 헤더

이 헤더는 기본적으로 이렇게 설정합니다:

```http
X-Content-Type-Options: nosniff
```

의미:

> “브라우저야, 응답의 `Content-Type`을 네 멋대로 추측(snoop/sniff)하지 말고, 서버가 지정한 MIME 타입 그대로만 처리해.”

<br>

### 🧠 브라우저는 기본적으로 **MIME Sniffing**을 함

브라우저들은 “서버가 Content-Type을 잘못 보낼 수도 있다”고 생각해서,
응답 본문 내용을 보고 **“이건 HTML 같네, 이건 JS 같네”** 식으로 *추측(sniff)* 하는 기능이 있어요.

예:

```http
Content-Type: text/plain
```

이지만 내용이 사실 `<script>alert(1)</script>`라면
→ 일부 브라우저는 “이건 자바스크립트 파일이네” 하고 실행해버림 ❗

<br>

### ⚠️ `X-Content-Type-Options` 헤더가 없을 때 생길 수 있는 공격들

(1) **Stored / Reflected XSS 확대 (MIME confusion)**

만약 공격자가 **파일 업로드나 게시물 첨부 기능**을 악용해
`text/plain`으로 업로드된 HTML/JS 코드를 올린 뒤,
그 파일이 `/uploads/file123.txt`로 접근 가능하다면,

브라우저가 MIME sniffing을 수행하면 이렇게 됩니다 👇

1. 서버 응답 헤더:

   ```http
   Content-Type: text/plain
   ```
2. 파일 내용:

   ```html
   <script>alert('XSS');</script>
   ```
3. 브라우저가 “이거 HTML/JS 같네?” → 실행 ❌ (XSS 발생)

`X-Content-Type-Options: nosniff`가 있으면
→ “서버가 text/plain이라 했으니 그냥 텍스트로 보여줌”
→ 코드 실행 안 됨 ✅

<br>

(2) **Cross-Domain Script Inclusion (MIME Type Confusion via JS)**

다른 사이트에서 이런 식으로 스크립트를 불러온다고 가정해봅시다:

```html
<script src="https://cdn.victim.com/uploads/profile.jpg"></script>
```

만약 `profile.jpg`가 사실상 JavaScript 코드이지만 서버가 `image/jpeg`으로 응답한다면?

* 브라우저가 “이건 사실 스크립트네?” → 실행할 수도 있음.
* 이 경우, `victim.com`의 쿠키/세션 정보가 공격자 사이트로 유출될 수 있음.

`nosniff` 헤더가 있으면
→ 브라우저가 “MIME이 이미지인데 JS로 쓰려 하네, 실행 안 함.”

<br>

(3) **Content-Type 오탐 방어 불가능**

개발자들이 실수로 API 응답을 `text/html`로 보내면,
브라우저가 HTML로 해석해서 DOM에 삽입하려 시도 → 스크립트 실행 우발 가능.

---

## 🧩 `Content-Security-Policy` (CSP)
**CSP는 브라우저에게 “무엇을 실행할지”를 엄격히 알려주는 보안 규칙입니다.**

```http
Content-Security-Policy: default-src 'self';
```

이 한 줄의 의미는:

> “이 페이지에서는 같은 출처(도메인)에서 온 콘텐츠만 실행하고,
> 외부 JS·이미지·CSS·iframe 등은 전부 차단해라.”

즉, 브라우저가 페이지 안의 **리소스 로딩 및 실행 경로를 강제로 제한**합니다.
서버는 CSP를 통해 클라이언트(브라우저)에 보안 규칙을 전달하는 거예요.

<br>

### 🔒 왜 필요한가?

**XSS(Cross-Site Scripting)** 공격이 들어올 때 CSP가 설정돼 있으면 브라우저가 이렇게 판단합니다 👇

> “이 스크립트가 ‘허용된 출처’에서 온 게 아니네? → 실행하지 않음 🚫”

| 공격 유형             | CSP 방어 여부 | 설명                    |
| ----------------- | --------- | --------------------- |
| **Reflected XSS** | ✅         | 인라인 스크립트 차단           |
| **Stored XSS**    | ✅         | 외부 리소스 로드 제한          |
| **DOM-based XSS** | ⚠️        | 부분 방어 (코드 로직에 따라 달라짐) |
| **Clickjacking**  | ❌         | `X-Frame-Options` 필요  |
| **데이터 유출 via JS** | ✅         | `connect-src` 제한으로 방지 |


<br>

### 🧠 주요 CSP 지시어(Directive)

| 지시어             | 역할                           | 예시                                          |
| --------------- | ---------------------------- | ------------------------------------------- |
| **default-src** | 기본 리소스 허용 범위                 | `default-src 'self'`                        |
| **script-src**  | 자바스크립트 파일/인라인 허용 범위          | `script-src 'self' https://cdn.example.com` |
| **style-src**   | CSS / 스타일 시트 출처              | `style-src 'self' 'unsafe-inline'`          |
| **img-src**     | 이미지 파일 출처                    | `img-src 'self' data:`                      |
| **font-src**    | 폰트 파일 출처                     | `font-src https://fonts.googleapis.com`     |
| **frame-src**   | iframe, embed 허용 범위          | `frame-src 'self' https://youtube.com`      |
| **connect-src** | AJAX, WebSocket, fetch 요청 대상 | `connect-src 'self' api.example.com`        |
| **object-src**  | Flash, PDF, Applet 등 임베드 객체  | `object-src 'none'`                         |
| **base-uri**    | `<base>` 태그의 허용 출처           | `base-uri 'self'`                           |
| **form-action** | `<form>` 제출 대상 제한            | `form-action 'self'`                        |

---

## 🧩 `Referrer-Policy` 헤더
**브라우저가 다른 사이트로 요청을 보낼 때 "Referrer(어떤 페이지에서 왔는지)" 정보를 얼마나 포함할지**를 결정하는 **보안 HTTP 헤더**입니다.

```http
Referrer-Policy: strict-origin-when-cross-origin
```

위 예시 정책은:

* 내부 페이지 이동 → Referrer 정상 유지
* 외부 사이트 이동 → 민감한 path는 제거하고 origin만 전달
* https → http로 이동 시 referrer 제거

→ 보안 + 편의성 둘 다 확보된 균형 잡힌 정책입니다.

<br>

### 🔒 왜 중요한가?

URL에는 다음과 같은 민감 정보가 들어갈 수 있습니다:

* 사용자 ID
* 세션 토큰
* 검색어
* 주문 ID
* 내부 페이지 경로
* 피싱/공격 분석 정보

Referrer가 외부로 넘어가면 **개인정보 유출**, **내부 URL 노출**, **보안 토큰 유출** 위험이 있어요.

그래서 Referrer-Policy로 이를 제한합니다.

<br>

### ⭐ Referrer-Policy 값 정리

| 설정값                                       | 의미                                | 보안 수준           |
| ----------------------------------------- | --------------------------------- | --------------- |
| **no-referrer**                           | 어떤 요청에도 Referrer를 절대 보내지 않음       | 🔐 매우 안전        |
| **no-referrer-when-downgrade** (기본값이었던 값) | HTTPS → HTTP로 갈 때는 Referrer 제거    | ⚠️ 안전하지 않음      |
| **origin**                                | 전체 URL 대신 **도메인만 전달**             | 🙂 안전           |
| **origin-when-cross-origin**              | 같은 도메인 → 전체 URL, 다른 도메인 → origin만 | 😀 일반적으로 추천     |
| **same-origin**                           | 같은 출처일 때만 Referrer 보냄             | 🔐 매우 안전        |
| **strict-origin**                         | HTTPS → HTTPS일 때만 origin 보냄       | 🔐 더 안전         |
| **strict-origin-when-cross-origin**       | 대부분의 브라우저에서 권장되는 안전한 디폴트          | 🔐 강력 추천        |
| **unsafe-url**                            | 항상 전체 URL을 전송                     | ❌ 매우 위험, 쓰면 안 됨 |

<br>

### 🛡️ 정책 미적용 시 위험

(1) **URL의 민감 파라미터가 외부로 그대로 전달됨**

```
https://site.com/dashboard?token=ABC123
```

사용자가 외부 링크 클릭 → Referrer 모두 전송
→ 토큰/이메일/검색어 등 유출 가능

<br>

(2) **내부 API 경로가 외부에 노출됨**

공격자에게 시스템 구조를 알려줘
→ 공격 난이도 낮아짐

<br>

(3) **로그인/마이페이지 같은 민감 페이지 정보가 외부로 전달됨**

→ 개인정보 유출

<br>

### 👁️ 예시

사용자가 페이지에서 외부 사이트 링크를 클릭할 때:

```
https://mybank.com/account?user=kim&balance=120000
```

Referrer-Policy가 없으면 외부 사이트는 이렇게 받음:

```
Referrer: https://mybank.com/account?user=kim&balance=120000
```

**계좌 정보가 그대로 다 노출됨** → 심각한 정보 유출

하지만 다음 헤더가 있다면:

```http
Referrer-Policy: strict-origin-when-cross-origin
```

외부 사이트는 이렇게만 받음:

```
Referrer: https://mybank.com
```

민감한 path / querystring 모두 숨겨짐.

---
