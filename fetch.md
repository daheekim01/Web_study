## 🌠**`fetch()` 함수**

#### 개요

`fetch()`는 **웹 브라우저**에서 **HTTP 요청**을 비동기적으로 보내고 **응답**을 처리할 수 있는 JavaScript API입니다. 주로 **AJAX** 요청을 처리하는 데 사용되며, `Promise`를 반환하는 비동기 함수입니다.

#### 기본 문법

```javascript
fetch(url, options)
  .then(response => response.json())  // 응답을 JSON 형태로 처리
  .then(data => console.log(data))    // 데이터를 처리
  .catch(error => console.log('Error:', error));  // 오류 처리
```

* `url`: 요청을 보낼 **URL** (필수)
* `options`: 요청에 대한 **옵션**을 설정하는 객체 (선택)

#### 주요 옵션 (`options` 객체)

* **method**: HTTP 요청 메서드 (GET, POST, PUT, DELETE 등). 기본값은 `GET`.
* **headers**: 요청 헤더. 예를 들어, 인증 토큰을 포함하거나 콘텐츠 타입을 설정할 때 사용.
* **body**: 요청 본문(body). POST나 PUT 요청에서 데이터를 전송할 때 사용.
* **mode**: CORS 정책을 설정하는 옵션. 기본값은 `cors`, 다른 값으로는 `no-cors`, `same-origin`, `navigate` 등이 있습니다.
* **credentials**: 인증 정보 전송 여부. 기본값은 `same-origin`이며, 다른 옵션으로는 `include`, `omit` 등이 있습니다.

#### 예시 1: **GET 요청**

```javascript
fetch('https://api.example.com/data')
  .then(response => response.json())  // 응답을 JSON으로 파싱
  .then(data => console.log(data))    // 데이터를 콘솔에 출력
  .catch(error => console.error('Error:', error));  // 오류 처리
```

* **GET** 요청을 보내고 응답을 JSON으로 처리하는 기본적인 예시입니다.

#### 예시 2: **POST 요청**

```javascript
const data = { username: 'example', password: 'password123' };

fetch('https://api.example.com/login', {
  method: 'POST',  // POST 요청
  headers: {
    'Content-Type': 'application/json',  // JSON 형식으로 전송
  },
  body: JSON.stringify(data),  // 데이터를 JSON 문자열로 변환하여 본문에 담기
})
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

* **POST** 요청을 사용하여 데이터를 **JSON 형식**으로 서버에 보내는 예시입니다.

#### 예시 3: **헤더 설정**

```javascript
fetch('https://api.example.com/user', {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer YOUR_ACCESS_TOKEN',  // 인증 토큰 헤더에 추가
    'Accept': 'application/json',  // 서버에서 JSON 응답을 원한다고 명시
  },
})
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

* **헤더**를 설정하여 인증 토큰을 포함한 요청을 보내는 예시입니다.

#### 예시 4: **CORS (Cross-Origin Resource Sharing) 처리**

```javascript
fetch('https://api.example.com/data', {
  method: 'GET',
  mode: 'cors',  // CORS 정책을 설정
})
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

* **CORS** 정책을 설정하여, 다른 도메인에서 오는 요청을 처리할 수 있게 합니다.

---

### **`fetch()`의 동작 원리**

1. **Promise 기반 비동기 처리**: `fetch()`는 요청이 완료될 때까지 기다리지 않고 바로 **Promise**를 반환합니다. 이를 통해 네트워크 요청을 **비동기적으로** 처리합니다.

   * **성공 시**: `then()` 메서드를 사용해 응답을 처리합니다.
   * **실패 시**: `catch()` 메서드를 사용해 오류를 처리합니다.
   * **Promise 반환**: `fetch()`는 `Promise` 객체를 반환하여 `.then()`과 `.catch()`를 사용해 **반응을 처리**할 수 있습니다.

2. **응답 처리**:

   * 응답 객체(`response`)에는 `status`, `headers`, `body` 등 HTTP 응답 관련 정보가 포함됩니다.
   * 예를 들어, `response.json()` 메서드를 사용하면 응답을 JSON 형식으로 파싱할 수 있습니다.

3. **CORS (Cross-Origin Resource Sharing)**:

   * `fetch()`는 CORS 정책을 자동으로 적용합니다. 즉, **다른 도메인에서 오는 요청**에 대해 서버가 `Access-Control-Allow-Origin` 헤더를 설정하지 않으면 **브라우저가 요청을 차단**합니다.
   * 이를 해결하려면 서버에서 CORS 설정을 맞춰줘야 합니다.

4. **옵션 설정**:

   * `fetch()`는 **옵션 객체**를 통해 다양한 설정을 지원합니다. 예를 들어, `method`, `headers`, `body` 등을 설정하여 **POST**나 **PUT** 요청을 보낼 수 있습니다.

---



### **예시. Reflected XSS (반사형 XSS)** 

#### **공격 시나리오**:

1. 사용자가 URL에 포함된 데이터를 \*\*`fetch()`\*\*를 통해 서버로 요청하고, 그 응답을 HTML로 삽입한다고 가정합니다.
2. 이때, 사용자가 URL에 **악성 스크립트**를 포함시켜 보내면, 서버가 이를 반영할 수 있습니다. 이 악성 스크립트가 웹 페이지에 삽입되어 실행됩니다.

#### **예시 (페이로드 포함 URL 조작)**:

1. **악성 페이로드**를 포함한 URL을 피해자에게 보냅니다.

   ```url
   https://example.com/search?query=<script>alert('XSS')</script>
   ```

2. 공격자가 **XSS 공격**을 유도하려는 페이지에서 사용된 **`fetch`** 함수는 쿼리 매개변수 `query`를 사용하여 서버로 요청하고, 응답을 반영하여 페이지에 표시합니다.

   ```javascript
   fetch(`https://example.com/search?query=${queryParam}`)
     .then(response => response.text())  // 응답을 텍스트로 받아옴
     .then(html => document.getElementById('results').innerHTML = html)  // 결과를 DOM에 삽입
     .catch(error => console.error('Error:', error));
   ```

3. 공격자는 URL을 통해 다음과 같은 **악성 스크립트**를 삽입하고, 이 스크립트가 \*\*`innerHTML`\*\*을 통해 웹 페이지에 삽입됩니다.

   ```html
   <div id="results">
     <script>alert('XSS')</script>
   </div>
   ```

4. 웹 페이지가 로드되면서 `alert('XSS')`가 실행되어 **XSS 공격**이 성공합니다.

#### **XSS 공격 방어 방법**:

* **입력 값 필터링**: `queryParam`과 같은 사용자 입력을 서버나 클라이언트 측에서 **검증**하고 **필터링**합니다.
* **출력 이스케이프**: 사용자 입력이 HTML에 포함될 때는 **이스케이프** 처리하여 `<`, `>`, `&`, `'` 등 특수 문자가 HTML 태그로 해석되지 않도록 합니다.
* **`Content Security Policy (CSP)`**: 스크립트 실행을 제한하는 **CSP**를 설정하여 악성 스크립트 실행을 방지할 수 있습니다.



