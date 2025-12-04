# 🥫서버가 Smuggling에 취약한지 확인하는 안전한(desync‑safe) 테스트 절차

---

# ✅ GET만 허용하는 서버일 때

✔ 서버가 **GET 바디, 헤더 우회, 경계 처리 등**에 대해 취약한지 확인
✔ 서버 상태 변화 X
✔ DoS·트래픽 폭주 X
✔ 민감 데이터 접근 X

아래 방법은 공개 취약점 연구에서 사용되는 “Minimal Risk Desync Test” 패턴을 기반으로 했다.

---

# 🧪 1단계: **GET Body 허용 여부 확인 (비(非)표준이지만 가능한)**

GET 요청은 보통 바디가 없지만, 일부 서버/프록시는 바디를 처리하거나,
프론트엔드·백엔드 처리 방식이 달라서 Smuggling이 발생할 수 있음.

다음은 가장 안전한 형태의 테스트:

### ▶ 테스트 요청

```
GET /test?probe=1 HTTP/1.1
Host: your-domain.com
Content-Length: 5

HELLO
```

### ✔ 기대되는 동작

* 정상 서버: “Content-Length 무시”, “바디 무시”, 그냥 `/test?probe=1` 처리
* 취약 서버:

  * 백엔드가 HELLO를 읽고 내부적으로 다음 요청에 붙여버리거나
  * 응답이 지연되거나
  * 엉뚱한 라우트로 보내지거나
  * 400/411 오류가 발생

### ✔ 왜 안전한가?

* HELLO는 비위험 문자열
* 서버가 이를 실행하거나 저장하지 않음
* 트래픽 영향도 없음

만약 **응답이 비정상적으로 느려지거나, 다음 요청이 깨지는 패턴**이 관찰되면
GET body 기반 HRS 가능성이 있다.

---

# 🧪 2단계: **GET + Transfer-Encoding 허용 여부 확인**

GET으로 chunked 인코딩을 보내면, 일부 서버는 이를 처리해버리면서
프론트엔드/백엔드 불일치가 발생할 수 있다.

### ▶ 테스트 요청

```
GET /test?probe=2 HTTP/1.1
Host: your-domain.com
Transfer-Encoding: chunked

0
```

### ✔ 취약하면 어떻게 되나?

* 프론트엔드는 chunked를 무시
* 백엔드는 chunked로 파싱하려 해서

  * connection hang
  * 다음 요청이 corrupted
  * 예측 불가능한 경계 불일치

→ 이런 **이상 징후 = Smuggling 가능성 매우 높음**

### ✔ 안전성

* chunk 크기 0이라 body 없음
* 서버 부하 없음
* 상태 변화 없음

---

# 🧪 3단계: **헤더 파싱 불일치(Header Smuggling) 테스트**

이건 가장 안전한 방법 중 하나.
바디가 전혀 필요 없고, 요청 한 개로 서버의 파싱 차이를 관찰할 수 있음.

예시는 다음처럼 “한쪽은 인식, 다른 쪽은 무시”하는 헤더를 넣는 방식이다.

---

## (A) 공백/탭 기반 헤더 우회 테스트

### ▶ 페이로드

```
GET /test?probe=3 HTTP/1.1
Host: your-domain.com
Transfer-Encoding : chunked
X-Probe: abc

```

여기서 `"Transfer-Encoding␣:"` (공백 포함)은

* 어떤 프록시는 정상 헤더로 인식
* 어떤 백엔드는 무시
  → 이 불일치가 있으면 HRS의 전제가 성립한다.

### ✔ 관찰 포인트

* 응답 길이가 평소보다 다름
* 예측 못 한 400/411 발생
* 커넥션이 비정상적으로 close/keep-alive
* 두 번째 요청이 깨짐

---

## (B) 비정상 인코딩 헤더

```
GET /test?probe=4 HTTP/1.1
Host: your-domain.com
Transfer-Encoding: chunķed
```

(여기서 k에 악센트를 넣은 변종)

* 프록시: 인식 or 오류
* 백엔드: 무시 or 정상 인식

**이 차이가 난다면 Smuggling 가능성이 있음.**

---

# 🧪 4단계: **Connection Desync Test (가장 중요한 테스트)**

HRS는 결국 “다음 요청이 깨지는가?”를 보는 공격이기 때문에
연속 요청을 하나의 TCP 연결에서 보내서 “두 번째 요청”이 영향을 받는지 확인할 수 있다.

이것도 무해한 패턴만 사용.

---

### ▶ 두 요청 연속 보내기

```
GET /test?probe=5 HTTP/1.1
Host: your-domain.com
Content-Length: 6

ABCDEF
GET /test?second=1 HTTP/1.1
Host: your-domain.com

```

### ✔ 정상 서버

* 첫 요청은 GET body 무시 → `/test?probe=5` 응답
* 두 번째 요청은 정상 → `/test?second=1` 응답

### ✔ 취약 서버(프록시/백엔드 경계 불일치)

* 두 번째 요청이 깨지거나
* 첫 번째 요청이 비정상적으로 지연
* 두 번째 요청이 백엔드에 도달하지 않음
* 응답이 통째로 엉킴

**이것은 가장 강력한 HRS 취약성 시그널이다.**

---

# 🟢 이렇게 하면 절대적인 안전 확보

이 테스트들은:

* 서버 데이터 변조 없음
* 인증/세션 손대지 않음
* 기능 변경 없음
* 서버에 큰 부하 없음
* 헌팅용 non-destructive 테스트

즉, “취약한지 보기 위한 관찰” 수준에 딱 맞음.

---

# 📌 요약 – GET-only 환경에서 HRS 취약점 안전하게 확인하는 법

| 목적                 | 테스트 방식                  | 위험도   |
| ------------------ | ----------------------- | ----- |
| GET body 처리 확인     | GET + Content-Length    | 매우 안전 |
| chunked 처리 확인      | GET + Transfer-Encoding | 매우 안전 |
| header mismatching | 공백/탭, encoding 변종       | 매우 안전 |
| 실제 desync 관찰       | 연속 GET 요청 보내기           | 안전    |

---

# 🥡 템플릿

✅ **1) curl로 실행 가능한 테스트 스크립트 세트**
✅ **2) Burp Repeater에서 그대로 붙여 넣는 요청 템플릿**
✅ **3) “정상” vs “취약” 응답 비교 체크리스트**

**절대 서버 가용성을 침해하지 않는 페이로드만 사용함.**
(바디에 악성 데이터 없음, 상태 변경 없음)

---

# ✅ 1) Curl 테스트 스크립트 세트

각 테스트는 “서버가 GET 요청에서 body나 TE를 잘못 처리하는지”를 확인하는 형태야.

---

## 🔹 Test 1 — GET Body 처리 여부

프론트엔드와 백엔드가 GET body 처리 방식이 다르면 Smuggling 가능성 있음.

```
curl -i -X GET "https://your-domain.com/test?probe=1" \
  -H "Content-Length: 5" \
  --data "HELLO"
```

📌 **정상이면**

* Body 무시
* 정상 응답

📌 **취약하면**

* 응답 지연
* 400/411 등 비정상 코드
* 커넥션이 timeout
* 다음 요청이 깨짐 (Burp에서 직접 확인 가능)

---

## 🔹 Test 2 — GET + Transfer-Encoding 처리 여부

```
curl -i "https://your-domain.com/test?probe=2" \
  -H "Transfer-Encoding: chunked" \
  --data-binary "0\r\n\r\n"
```

📌 **정상**: TE 무시 / 200 정상
📌 **의심**: hang, 비정상 종료, 400, 서버가 chunk 파싱 시도

---

## 🔹 Test 3 — Header 우회(공백) 처리 여부

```
curl -i "https://your-domain.com/test?probe=3" \
  -H "Transfer-Encoding : chunked"
```

📌 **정상**: TE 인식 안 하고 그냥 200
📌 **취약**:

* TE가 인식돼 chunk parsing 시도
* 400 발생
* 커넥션이 빨리 끊김

---

## 🔹 Test 4 — Header 인코딩 변종

```
curl -i "https://your-domain.com/test?probe=4" \
  -H $'Transfer-Encoding: chunķed'
```

📌 비정상 파싱 = 헤더 Smuggling 가능성.

---

## 🔹 Test 5 — 연속 요청(Connection desync) 테스트

이건 curl로는 어렵고, `nc` 또는 Burp Repeater 사용 권장.
그래도 curl에서 최소 테스트를 하려면 이렇게:

```
printf "GET /test?probe=5 HTTP/1.1\r\nHost: your-domain.com\r\nContent-Length: 6\r\n\r\nABCDEFGET /test?second=1 HTTP/1.1\r\nHost: your-domain.com\r\n\r\n" | nc your-domain.com 80
```

📌 **정상**

* 두 요청 모두 정상적으로 처리됨

📌 **취약**

* 두 번째 응답이 깨짐
* 첫 요청 시간 이상하게 길어짐
* 두 번째 요청이 전달되지 않음

---

# ✅ 2) Burp Repeater 요청 템플릿 (복붙용)

Burp로 테스트하는 것이 **정확도 가장 높음**.

---

## 🔹 Template 1 — GET Body

```
GET /test?probe=1 HTTP/1.1
Host: your-domain.com
Content-Length: 5

HELLO
```

---

## 🔹 Template 2 — GET + Chunked

```
GET /test?probe=2 HTTP/1.1
Host: your-domain.com
Transfer-Encoding: chunked

0
```

---

## 🔹 Template 3 — Header whitespace bypass

```
GET /test?probe=3 HTTP/1.1
Host: your-domain.com
Transfer-Encoding : chunked

```

---

## 🔹 Template 4 — Encoded TE header

```
GET /test?probe=4 HTTP/1.1
Host: your-domain.com
Transfer-Encoding: chunķed

```

---

## 🔹 Template 5 — **연속 요청 테스트 (가장 중요)**

Burp Repeater는 "Connection: close"를 제거하고 **두 요청을 그대로 붙여 넣기** 기능을 지원함.

```
GET /test?probe=5 HTTP/1.1
Host: your-domain.com
Content-Length: 6

ABCDEF
GET /test?second=1 HTTP/1.1
Host: your-domain.com

```

👉 두 번째 요청이 **깨지면 = Smuggling 취약**

---

# ✅ 3) “정상” vs “취약” 결과 비교 체크리스트

### ✔ 정상(안전)

* 모든 테스트에서 **응답이 즉시 옴**
* 항상 **200 / 정상 오류(400등)**만 반환됨
* **두 번째 요청이 절대 깨지지 않음**
* 서버 로그에서 예외 없음
* chunked 파싱 로그 없음

### ❌ Smuggling 가능성 높은 경우

* GET Body에서 **응답이 지연되거나 400이 뜸**
* chunked 요청에서 **서버가 chunk 파싱하려는 로그**
* whitespace header 우회에서 **이상한 parsing 행동**
* 두 개 연속 요청 중 **두 번째 요청이 깨짐**
* 커넥션이 조기 종료되거나 timeout
* 라우팅이 바뀌거나 Host가 왜곡됨

**위 중 하나라도 뜨면 “조심스럽게 취약 가능성 있음”으로 분류해야 한다.**

---
두 번째 요청이 “깨졌는지(broken)” 확인하는 방법은 **툴(브라우저/버프/터미널)**에 따라 조금씩 다르지만,
패턴은 매우 명확해.

아래에서

* **Burp Repeater**
* **curl/nc(터미널)**
* **서버 로그**
  에서 각각 어떻게 식별하는지 가장 쉬운 기준으로 알려줄게.

---

# ✅ 1) Burp Repeater에서 확인하는 방법 (가장 쉬움)

Repeater에서 이렇게 **두 개의 요청을 한 연결에서 보내는** 템플릿을 쓴다고 하자:

```
GET /test?probe=5 HTTP/1.1
Host: your.com
Content-Length: 6

ABCDEF
GET /test?second=1 HTTP/1.1
Host: your.com

```

전송하면 Burp는 아래 순서로 응답을 보여준다.

---

## ✔ 정상(안전한 서버)일 때

Burp에서 응답이 **두 개 또는 하나로 깔끔**하게 나온다:

### 예 1) 응답이 두 번 분리되어 그림처럼 보임

```
HTTP/1.1 200 OK
... (첫 번째 요청의 내용)

HTTP/1.1 200 OK
... (두 번째 요청의 내용)
```

### 예 2) HTTP 서버가 keep-alive를 끊어서 하나씩 처리할 수도 있음

둘 중 어떤 형태든 “두 번째 요청이 정상 라우팅돼 응답이 온다”면 정상.

---

## ❌ 취약할 때 발생하는 특징적인 패턴

### ❌ 패턴 1 — 두 번째 요청이 통째로 사라짐

```
HTTP/1.1 200 OK
... (첫 요청)
```

그리고 Burp가 다음 응답을 기다리다가 timeout
→ **소켓에서 두 번째 요청이 처리되지 않았다는 의미**

---

### ❌ 패턴 2 — 두 번째 요청이 엉뚱한 URL로 갔거나 합쳐짐

예를 들어 이렇게 뜬다:

```
HTTP/1.1 404 Not Found
Requested URL: /test?probe=5ABCDEFGET /test?second=1
```

→ 서버가 요청 경계를 잘못 파싱했다는 **명백한 HRS 신호**

---

### ❌ 패턴 3 — 두 번째 응답이 매우 늦게 오거나, 첫 번째 응답이 이상하게 느려짐

이건 desync가 발생해 백엔드가 잘못된 경계를 기다리고 있는 상태.

---

### ❌ 패턴 4 — 응답이 아예 연결이 끊기며 끝남 (Connection closed)

두 번째 요청이 처리되기 전에 백엔드가 접속 종료함.

---

# ✅ 2) netcat(nc)으로 확인하는 방법

두 요청을 이렇게 밀어넣는다고 하자:

```
printf "GET /test?probe=5 HTTP/1.1\r\nHost: your.com\r\nContent-Length: 6\r\n\r\nABCDEFGET /test?second=1 HTTP/1.1\r\nHost: your.com\r\n\r\n" \
| nc your.com 80
```

---

## ✔ 정상(안전)

출력에는 **두 번의 HTTP 상태 코드(예: 200 200)**가 나타난다.

예:

```
HTTP/1.1 200 OK
... (Response 1)

HTTP/1.1 200 OK
... (Response 2)
```

---

## ❌ 취약

아래 중 하나라도 나타나면 문제:

### 1) 응답이 **한 개만 보이고 종료**

```
HTTP/1.1 200 OK
... (Response 1)
```

→ 두 번째 요청이 이벤트를 타지 못함

### 2) 출력이 중간에서 꼬임

```
HTTP/1.1 200 OK
...DATA...
HTTP/1.1 404 Not FoundGET /test?second=1 Host:
```

### 3) nc가 **timeout**되거나 서버가 너무 오래 반응 없음

---

# ✅ 3) 서버 로그로 확인하는 방법 (추가적인 매우 강력한 단서)

서버 로그에서 다음을 보면 취약 가능성 매우 높음:

---

### ❌ 패턴 1 — 첫 요청 로그만 남고 두 번째 요청 로그 없음

예시 (nginx access.log):

```
10.0.0.1 - - "GET /test?probe=5 HTTP/1.1" 200 123 "-" "-"
# second=1 요청 없음
```

---

### ❌ 패턴 2 — 이상한 URL 로그

서버가 바이트를 잘못 이어붙인 경우:

```
"GET /test?probe=5ABCDEFGET /test?second=1 HTTP/1.1 HTTP/1.1" 400
```

---

### ❌ 패턴 3 — 400, 411, 413 등 비정상적인 오류 다발

특히:

* 400 Bad Request
* 411 Length Required
* 413 Payload Too Large
* 426 Upgrade Required
* 500 Internal Error

이런 게 **연속 요청 테스트 수행 시** 반복되면 매우 강력한 Smuggling 신호.

---

# 📌 핵심 요약

**두 번째 요청이 깨졌다는 의미는 다음 중 하나를 만족할 때다:**

| 증상                | 의미                              |
| ----------------- | ------------------------------- |
| 두 번째 요청의 응답이 없음   | 요청이 백엔드까지 가지 못함 → desync 발생     |
| 두 번째 URL이 섞여서 들어감 | 경계 파싱 오류 → Smuggling 조건 성립      |
| 응답이 비정상적으로 느려짐    | 백엔드가 잘못된 Content-Length/TE를 기다림 |
| 로그에 두 번째 요청이 없음   | 백엔드가 그 요청을 버렸다는 뜻               |
| 연결이 응답 중단 후 닫힘    | 프론트/백엔드 파싱 불일치                  |

이 중 **하나라도 뜨면 취약 가능성 HIGH**야.

---

# 👍 원하면 다음도 만들어줄게

* “취약성 발견됐을 때 추가로 확인해야 할 단계”
* “안전하게 Proof-of-Concept 만드는 방법”
* “서버 타입(Nginx/Apache/HAProxy)별 Smuggling 방지 설정”
* “GET-only 서버를 완전히 HRS-resistant하게 만드는 체크리스트”

