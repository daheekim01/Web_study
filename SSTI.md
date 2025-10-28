## SSTI/Expression Injection (서버사이드 템플릿/표현식 주입 시도)

SSTI(Server-Side Template Injection)는 서버 측에서 사용하는 템플릿 엔진이 사용자 입력을 적절하게 필터링하지 않으면 발생할 수 있는 취약점입니다. 이 취약점은 공격자가 템플릿 엔진의 기능을 악용하여 서버 측에서 코드를 실행할 수 있게 만듭니다.

`#{ ... }` 표기법은 여러 템플릿/표현식 문법에서 **내부 표현식(Interpolation / expression)** 으로 사용.
템플릿 엔진이 `#{ ... }` 같은 표현을 평가하면 **서버 측에서 코드가 실행되거나 값이 반환**됩니다.
* 예: Ruby/GString, 일부 템플릿 엔진, 몇몇 프레임워크의 표현식 문법 등에서 평가

---

## 예시 1
```
https://example.com/recv_adjust_postback.php?app_id\s8786990&tracker\=1tlu299o&tracker_name\=Mobusi%3A%3Aunknown%3A%3Atest%23%7B+777+%2A+777+%7D%3A%3A0&network_name\=Mobusi&campaign_name\=unknown&adgroup_name\=test%23%7B+777+%2A+777+%7D&creative_name\=0&created_at\61456249&click_time\61456249&country\=jp&city\=Tokyo&postal_code\1-0053&os_name\=macos&os_version\.9.3&activity_kind\=click
```
페이로드가 광고·리딤(postback) 파라미터에 섞여 있음 — 흔히 외부 값(광고 네트워크가 전달하는 문자열 등)을 템플릿에 바로 넣는 코드 경로(로그, 이메일 템플릿, 리포트 템플릿 등)를 노린 방식.
* postback : 광고 네트워크/광고 추적/리딤 시스템 등에서 서버→서버로 보내는 HTTP 요청(보통 GET/POST)



### URL 디코딩 ({777*777}이 인코딩되어 쿼리 파라미터 뒤에 들어가있는 상태)

`%3A%3A` → `::`
`%23%7B+777+%2A+777+%7D` → `#{ 777 * 777 }`

따라서 `tracker_name`(디코딩 후)는 대략:

```
Mobusi::unknown::test#{ 777 * 777 }::0
```

`adgroup_name`에도 동일 페이로드가 들어가 있음:

```
test#{ 777 * 777 }
```

`#{ 777 * 777 }` 은 공격자가 **템플릿/표현식 평가(산술식) 평가 여부를 테스트**하려고 넣은 탐지용 페이로드다. (777*777 = 603729)



### 취약한 코드 패턴

* 사용자 입력을 템플릿에 **검증·이스케이프 없이 직접 삽입**하는 렌더링 코드:
  `render(template, { tracker_name: params[:tracker_name] })` 같은 패턴(프레임워크/언어별로 다름).
* 로그·통계·이메일용 템플릿에서 사용자 입력을 이스케이프하지 않고 출력할 경우.
* 외부 SDK/라이브러리가 사용자 입력을 템플릿 식으로 포맷해서 내부에서 `eval`/`render` 하는 경우.

(코드 레벨 증거를 찾으려면 애플리케이션에서 `render`, `template`, `ERB`, `format`, `formatString` 등 사용처 검토)



### 성공 흔적(탐지 지표 IOC)

* 응답/로그에 `603729`(혹은 공격자가 넣은 산술 결과)가 출력되는 경우 — **취약성 징후**
* 요청에 `%23%7B` 또는 `#{`가 포함된 접근 기록
* `tracker_name`, `adgroup_name`, `creative_name` 등 외부 전달 파라미터에 표현식 삽입 흔적
* 대량의 postback/ad 트래픽에서 동일한 패턴 반복 (스캐닝 도구 사용 흔적)



---
## 다양한 페이로드

* `{{ 777*777 }}`

  * 흔한 표기: **Jinja2 (Python), Twig (PHP), Handlebars/Mustache 계열** 등.
  * 엔진에 따라 다름:

    * **Jinja2/Twig**: 일반적으로 표현식을 평가할 수 있음(변수/속성 접근, 연산 등). SSTI 가능성 존재.
    * **Mustache (logic‑less)**: 대개 연산/코드 실행을 하지 않으므로 단순히 문자열로 취급될 가능성 높음.
      
* `{{777*777}}` (스페이스 유무는 의미 없음 — 같은 시도)
  
* `<%\w7*777%>` (예시로 준 `<% ... %>` 계열)
  * `<% ... %>` 표기: **ERB (Ruby), EJS (Node), ASP-like** 템플릿에서 사용. 서버에서 렌더링되는 경우 내부 코드(언어 코드)를 실행할 가능성이 있음 
    
* `${777*777}`
  * `${...}` 표기: **Java/JSP EL, 일부 JS 템플릿, Velocity, Thymeleaf** 등에서 쓰임. 엔진에 따라 표현식 평가가 가능.

