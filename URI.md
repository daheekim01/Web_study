### 🎀 URI의 구성:

일반적으로 URI는 다음과 같은 형식으로 구성됩니다:

```
<스킴>://<호스트>/<경로>?<쿼리>#<프래그먼트>
```

예를 들어, `https://www.example.com:8080/path?query=1#fragment`

* **https**는 스킴
* \*\*[www.example.com\*\*은](http://www.example.com**은) 호스트
* **8080**은 포트
* **/path**는 경로
* **query=1**은 쿼리 파라미터
* **fragment**는 프래그먼트

**URI 스킴** (Uniform Resource Identifier Scheme)은 URI (Uniform Resource Identifier)의 한 부분으로, 리소스가 어떤 프로토콜을 사용해 접근되는지를 지정하는 역할을 합니다. URI는 웹 주소와 같은 자원의 위치를 나타내는데, 스킴은 이 자원에 접근하는 방법을 정의합니다.

예를 들어, URL(Uniform Resource Locator)은 URI의 일종이며, 그 안에서 스킴은 "http", "https", "ftp" 등으로 나타냅니다. 스킴은 리소스를 식별할 수 있는 방법을 알려주는 것이죠.

### URI 스킴의 예:

1. **http** – 웹 페이지를 요청할 때 사용하는 스킴 (예: `http://example.com`)
2. **https** – 보안된 웹 페이지 요청 시 사용하는 스킴 (예: `https://example.com`)
3. **ftp** – 파일 전송 프로토콜을 사용하여 파일을 접근할 때 사용하는 스킴 (예: `ftp://ftp.example.com`)
4. **mailto** – 이메일 주소를 나타낼 때 사용하는 스킴 (예: `mailto:user@example.com`)
5. **file** – 로컬 파일 시스템에서 파일을 접근할 때 사용하는 스킴 (예: `file:///C:/path/to/file`)

URI 스킴을 통해 리소스를 어떻게 접근할 수 있는지, 어떤 프로토콜이나 규칙을 사용해야 하는지 알려주기 때문에 웹에서 자원과의 상호작용에 중요한 역할을 합니다.

---

## 💻 예제 1: `data:` URL을 이용한 XSS (iframe + script)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Data URL XSS Example</title>
</head>
<body>
  <h1>Data URL을 이용한 XSS 데모</h1>

  <!-- iframe으로 data URL을 삽입 -->
  <iframe src="data:text/html,
    <script>alert('XSS! Data URL을 통해 실행됨');</script>"
    width="0" height="0" style="display:none;">
  </iframe>

</body>
</html>
```

### 🔍 설명:

* `iframe` 태그의 `src` 속성에 `data:text/html,<script>...</script>` 형태의 **스크립트가 포함된 HTML**을 넣었습니다.
* 브라우저는 이걸 **새 HTML 페이지처럼 인식**하고 렌더링하며, `<script>`가 실행됩니다.
* 즉, 이 방식으로 **스크립트를 외부 로드 없이 inline으로 실행**할 수 있습니다.

---

## 💻 예제 2: `data:` URL을 `<img>`에 쓰는 경우 (피싱이나 Clickjacking 등에 사용 가능)

```html
<!DOCTYPE html>
<html>
<body>
  <h2>Data URL 이미지 삽입</h2>
  <img src="data:image/svg+xml,
    <svg xmlns='http://www.w3.org/2000/svg' width='300' height='100'>
      <a href='javascript:alert(`Clicked!`)'>
        <text x='10' y='50' font-size='30'>Click Me</text>
      </a>
    </svg>">
</body>
</html>
```

### 🔍 설명:

* SVG 안에 `<a href="javascript:...">`를 넣으면, 클릭 시 자바스크립트가 실행됩니다.
* **보안에 취약한 브라우저나 환경**에서는 이렇게 악성 스크립트가 실행될 수 있습니다.
* 이미지처럼 보이지만, 실제로는 **인터랙티브한 스크립트 실행 트리거**로 작동할 수 있습니다.

