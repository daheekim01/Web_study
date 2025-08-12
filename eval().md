## 🔍 용어 정리

| 용어                              | 설명                                                        |
| ------------------------------- | --------------------------------------------------------- |
| **XSS (Cross-Site Scripting)**  | 자바스크립트 코드가 브라우저에서 실행됨                                     |
| **RCE (Remote Code Execution)** | 서버 측에서 임의의 코드가 실행됨                                        |
| **eval()**                      | 브라우저에서도 쓰이고, PHP 같은 서버언어에서도 쓰이는 **실행 함수**                 |
| **Attribute Injection**         | HTML 속성(attribute)에 악성 코드가 삽입됨 (ex: `onerror="alert(1)"`) |

---

## 🔍 `eval()`은 상황에 따라 다르게 해석됨

### 1. 📡 서버 측에서 eval() → RCE (PHP, Node.js 등)

예:

```php
eval($_GET['cmd']);  // 위험한 RCE
```

* 서버에서 임의 코드가 실행됨
* 이는 **XSS가 아니라 RCE**

  ## ✅ 예시 코드

```php
eval(base64_decode('...'));
```

→ 이건 **base64로 인코딩된 코드를 디코딩해서 실행**하겠다는 의미입니다.



## base64 디코딩 해석

'...'에 들어간 코드의 디코딩된 결과를 보면 다음과 같습니다:

```php
file_put_contents('baker.php', base64_decode('PD9waHAgY2xhcz0NFNDkzRjYYgeyBwdWJsaWMgZnVuY3Rpb24gX19jb25zdHJ1Y3QoJEh5NUY3...'))
```

### 🧨 의미:

* `file_put_contents('baker.php', ...)`
  → 서버에 `baker.php` 파일을 생성하고
* 그 안에 또 다른 **base64 인코딩된 PHP 웹쉘**을 저장


## 이중 인코딩된 웹쉘

`base64_decode(...)` 안에 또 다른 base64가 있으므로, 결과적으로는 다음처럼 됩니다:

```php
<?php
eval(
    base64_decode(
        base64_decode('...') // 이 안에 최종 웹쉘
    )
);
```

→ **이중 디코딩 후 eval로 실행되는 구조**는 흔한 **웹쉘 우회 기법** 중 하나입니다.


## 🚨 실제 기능 요약

| 항목       | 내용                                             |
| -------- | ---------------------------------------------- |
| 🧱 목적    | 서버에 `baker.php`라는 파일 생성                        |
| 📦 내용    | `baker.php` 안에 base64 인코딩된 PHP 코드 삽입           |
| 🔥 기능    | eval, base64\_decode 이용한 원격 명령 실행 백도어          |
| 🎯 최종 결과 | 공격자가 `baker.php?pass=...` 같은 방식으로 **명령 실행 가능** |


---

### 2. 🌐 클라이언트 측 HTML에서 eval() → XSS (JavaScript)

예:

```html
<script>
eval(location.hash.slice(1)); // → location.hash에 따라 JS 실행
</script>
```

* 사용자가 브라우저에 악성 자바스크립트를 삽입
* 이는 **XSS**

---

### 3. ✒️ Attribute Injection이 되는 경우

만약 페이로드가 아래처럼 HTML의 속성에 삽입된다면:

```html
<img src="x" onerror="eval(alert('XSS'))">
```

여기서는 **HTML 속성(`onerror`)에 eval이 들어감** → 이건 **Attribute Injection** 형태의 **XSS**입니다.

> 즉, `eval()`이 있다고 해서 무조건 Attribute Injection이 되는 게 아니라,
> **삽입 위치가 HTML 속성이었을 때** "Attribute Injection"이라고 부르는 거예요.

---

## 🔁 다시 질문으로 돌아가서:

> ❓ *"eval()이 들어간 페이로드가 왜 Attribute Injection으로 분류돼?"*

→ ✅ **HTML 속성 내부**에 삽입되어 있기 때문에, **Attribute Injection 유형의 XSS**로 분류되는 것.

---

## 💡 정리

| 상황                                        | 분류                                  |
| ----------------------------------------- | ----------------------------------- |
| `eval()`이 서버에서 실행                         | 🔥 RCE (예: PHP, Node.js)            |
| `eval()`이 `<script>` 안에서 실행               | 🧨 일반 XSS                           |
| `eval()`이 `<img onerror="...">` 같은 속성에 삽입 | 🚩 Attribute Injection (XSS의 하위 유형) |





