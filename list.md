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

### (1) **Stored / Reflected XSS 확대 (MIME confusion)**

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

### (2) **Cross-Domain Script Inclusion (MIME Type Confusion via JS)**

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

### (3) **Content-Type 오탐 방어 불가능**

개발자들이 실수로 API 응답을 `text/html`로 보내면,
브라우저가 HTML로 해석해서 DOM에 삽입하려 시도 → 스크립트 실행 우발 가능.

---



