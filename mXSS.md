## 🩻 mXSS (The Vulnerability Hiding in Your Code)

\*\*mXSS(Mutation XSS)\*\*는 HTML이 **브라우저에서 자동으로 "수정(mutate)"되는 방식**을 악용해서
**필터링(Sanitizer)을 우회**하는 XSS 공격입니다.

* 기존의 DOMPurify, bleach 등 필터링 시스템도 우회 가능
* 구글 검색, 이메일 서비스 등에서도 발견된 적 있음

---

## 🔧 HTML은 왜 이렇게 위험할까?

HTML은 굉장히 **관대한(tolerant)** 언어입니다.

예:
`<p>test` 라는 잘못된 HTML도 브라우저는
자동으로 `<p>test</p>`처럼 "고쳐서" 렌더링합니다.

### HTML이 관대한 이유:

| 이유      | 설명                           |
| ------- | ---------------------------- |
| **접근성** | HTML 오류 때문에 웹 콘텐츠가 깨지지 않도록 함 |
| **유연성** | 초보자도 HTML을 쉽게 쓸 수 있도록 함      |
| **호환성** | 예전 웹사이트들도 최신 브라우저에서 잘 보이도록   |

하지만… 이 **"자동 수리 기능"** 때문에 **mXSS** 같은 취약점이 생깁니다!

---

## 🔁 Mutation(변형) 이란?

**HTML Mutation** = 브라우저가 HTML을 렌더링하면서 **자동으로 수정하는 것**

예시:

| 입력             | 변형 결과                    | 설명       |
| -------------- | ------------------------ | -------- |
| `<p>test`      | `<p>test</p>`            | 태그 자동 닫힘 |
| `<a alt=test>` | `<a alt="test">`         | 속성 자동 수정 |
| `<table><a>`   | `<a></a><table></table>` | 구조 재정렬   |

**mXSS 공격자**는 이 동작을 역이용해서
**브라우저는 실행하지만, 필터링은 통과하는** 코드를 만들어냅니다.

---

## 🧠 HTML 파싱의 복잡성

HTML 파서는 7가지 서로 다른 방식으로 콘텐츠를 파싱합니다.

| 파싱 유형                  | 예시 태그                   | 특징                         |
| ---------------------- | ----------------------- | -------------------------- |
| **Void Elements**      | `<br>`, `<img>`         | 닫는 태그 없음                   |
| **Raw Text Elements**  | `<script>`, `<style>`   | 안의 내용 그대로 처리 (HTML 해석 안 함) |
| **Escapable Raw Text** | `<textarea>`, `<title>` | 특수 문자 이스케이프 처리             |
| **Foreign Content**    | `<svg>`, `<math>`       | 다른 네임스페이스 (파싱 규칙 다름)       |
| **Normal Elements**    | `<div>`, `<p>` 등        | 일반 HTML 처리                 |

### 예시 비교:

1. `<div><a alt="</div><img src=x onerror=alert(1)>">`
   → `<a>` 태그 내부 속성으로 처리됨 → **무해함**

2. `<style><a alt="</style><img src=x onerror=alert(1)>">`
   → style 내부는 raw text로 처리 → **실제 `<img>`가 실행됨** → XSS 발생!

---

## 🧬 Foreign Content 요소 (SVG 등)

`<svg>` 같은 요소는 HTML과 **다른 규칙**으로 파싱됩니다.

예시:

```html
<svg><style><a alt="</style><img src=x onerror=alert(1)">
```

* 이 경우 `<img>`가 실행됩니다.
* SVG 내부의 `<style>`은 "raw text"로 취급되지 않음 → **정상 HTML로 해석**

🔍 **이 네임스페이스 차이**를 이용하면 DOMPurify 같은 필터를 **우회**할 수 있습니다.

---

## 🧪 mXSS 하위 유형

mXSS는 다양한 방식으로 나뉘며, 단순한 XSS 우회 기술을 포함한 **포괄적인 용어**로 사용됩니다.

### 1. 파서 차이(Parser Differentials)

* 필터링할 때와 브라우저에서 **다른 방식으로 파싱되는 경우**
* 예: `<noscript>`는 JS가 **켜져 있을 때**와 **꺼져 있을 때** 파싱 방식이 다름

예시:

```html
<noscript><style></noscript><img src=x onerror="alert(1)">
```

* 필터링 도중에는 `<style>`이 무해하다고 판단되지만,
* 브라우저에서는 XSS 발생

---

### 2. 파싱 라운드트립(Parsing Round Trip)

* HTML은 **한 번 파싱할 때**와 **두 번 파싱할 때** 결과가 달라질 수 있음

예시:

```html
<form id="outer"><div></form><form id="inner"><input>
```

* 처음 파싱: 내부 `<form>`이 유지됨
* 재파싱: 내부 `<form>` 무시됨

→ 이 구조 변화를 악용해 필터 우회 가능

---

### 3. 네임스페이스 혼란 (Namespace Confusion)

* 예: `<form><math><style>` 조합을 사용해 HTML 파서를 속임
* DOMPurify는 안전하다고 판단하지만 브라우저는 `<style>`을 활성화함

```html
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

---

### 4. 디세니타이즈(Desanitization)

* 필터링한 콘텐츠를 **앱이 후처리하면서 다시 깨뜨리는 것**
* 필터링 후에 태그 이름을 바꾸거나 구조를 바꾸면 다시 XSS 발생

예시:

```html
<!-- 필터링된 출력 -->
<svg>...</svg>

<!-- 앱이 후처리로 태그 이름을 변경 -->
<custom-svg>...</custom-svg>
```

→ `custom-svg`는 SVG 네임스페이스가 아니므로 브라우저가 다르게 렌더링 → XSS 발생



## 🧪 예제 

* 기본적으로 DOMPurify는 `<script>`, `<img onerror>` 같은 코드를 차단합니다.
* 하지만 `<svg><style>` 내부에 `<img>`가 숨어 있을 경우, **파싱 네임스페이스가 달라지며 필터링이 실패할 수 있습니다.**
* 이 예제에서 사용된 페이로드는:

  ```html
  <svg><style><a alt="</style><img src=x onerror=alert(1)>
  ```

---

## 📌 핵심 요약

| 키워드                     | 설명                               |
| ----------------------- | -------------------------------- |
| **mXSS**                | 브라우저의 HTML "자동 수정"을 악용한 XSS      |
| **Mutation**            | 브라우저가 HTML을 파싱하며 자동으로 고치는 현상     |
| **Parser Mismatch**     | 필터링 툴과 브라우저 간의 파싱 방식 차이          |
| **Namespace Confusion** | SVG, MathML처럼 별도 파서 룰을 가진 태그를 악용 |
| **Desanitization**      | 필터 후 재가공 중 보안이 깨지는 경우            |

