### ❓ XML-RPC란?

**XML-RPC는 WordPress에서 사용하는 API**로,
개발자들이 WordPress 웹사이트와 **원격으로 통신**할 수 있도록 **통로를 제공**합니다. HTTP 프로토콜을 이용해 XML로 인코딩한 데이터를 교류할 수 있게 합니다.

---

### 🛠️ XML-RPC를 통해 가능한 작업들:

* 게시물 **작성**
* 게시물 **수정**
* 게시물 **삭제**
* 새 파일 **업로드**
* 댓글 **목록 가져오기**
* 댓글 **수정**

---

### 🔓 XML-RPC의 취약점(XML-RPC API authenticated methods)

XML-RPC에서 발생할 수 있는 **주요 보안 취약점**은 다음과 같습니다:

* 공격자가 `xmlrpc.php`를 이용하여 **워드프레스 로그인 시도**

  * 대표적인 공격 기법: **브루트포스 공격**
    (즉, 많은 아이디/비밀번호 조합을 빠르게 시도해서 로그인 성공을 노리는 방식)


---

### ☠️ XML-RPC를 통한 공격 시나리오 (해석):


1. **기본적으로 xmlrpc.php 파일에 접근하면 다음과 같은 화면이 보입니다**
   (예: 브라우저에서 아래 주소로 접속)

   ```
   http://<타겟 웹사이트>/<wordpress 디렉토리>/xmlrpc.php
   ```

2. **프록시 도구를 엽니다** (예: Burp Suite 사용)
   → 요청을 가로채서 다시 전송합니다.


3. **먼저 해야 할 일:**

   * `POST` 요청을 보내서 **사용 가능한 모든 메서드 목록을 요청**합니다.
   * 왜냐하면, 어떤 액션들이 가능한지를 알아야 공격을 설계할 수 있기 때문입니다.

#### 요청 예시:

```xml
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>
```


4. **응답에서 아래 메서드들을 찾습니다:**

   * `wp.getUsersBlogs`
   * `wp.getCategories`
   * `metaWeblog.getUsersBlogs`

> ✏️ 참고: 위 메서드 외에도 더 있습니다.


5. **이제 브루트포스 로그인을 수행할 차례입니다.**

   * `POST` 요청으로 아이디/비밀번호를 반복 시도합니다.
   * 만약 유효한 사용자명을 알고 있다면 더 유리합니다.
   * 유효한 사용자명을 찾기 위해 `wpscan` 도구 사용을 추천합니다.
   

---

* 위 https://medium.com/infosec-notes/wordpress-hacking-2025-03985e7d2e08 참고
* 아래 예제 https://takudaddy.tistory.com/547 참고

---


## 🔍 분석 요약

### 📌 `wp.getUsersBlogs`란?

* WordPress의 XML-RPC API 메서드 중 하나
* 호출 예시:

  ```xml
  <methodCall>
    <methodName>wp.getUsersBlogs</methodName>
    <params>
      <param><value><string>username</string></value></param>
      <param><value><string>password</string></value></param>
    </params>
  </methodCall>
  ```
* 목적: 주어진 **username**과 **password**로 해당 사용자의 블로그 목록을 가져오는 인증 API
* ❗ 즉, `wp.getUsersBlogs` 호출은 **로그인 시도**와 동일한 의미

---

## 🧠 공격 시나리오로 본다면?

1. 🔎 **공격자는 먼저 사용자 ID 목록을 수집**

   * WordPress는 기본적으로 `/?author=1` 등으로 ID를 유추할 수 있음
   * 또는 댓글/글 작성자 링크, REST API 등을 통해 사용자 ID가 노출될 수 있음

2. 🎯 그런 다음 공격자는 `wp.getUsersBlogs`에 대해 **브루트포스 또는 크리덴셜 스터핑** 시도

   * 이미 수집한 사용자 ID로
   * 여러 비밀번호 조합을 시도하여 로그인 성공 여부를 확인


## 🔒 보안적으로 의미하는 것

* **이 요청이 보였다면 이미 사용자 ID가 노출되었을 가능성이 큼**
* 공격자는 ID를 알고 있으니 **이제 목표는 비밀번호 추측**

---

## 🚨 위험 신호

| 항목                  | 설명                             |
| ------------------- | ------------------------------ |
| XML-RPC API 사용      | 많은 보안 취약점과 관련됨 (브루트포스, DDoS 등) |
| wp.getUsersBlogs 요청 | 인증 시도이며, 실패 응답 여부로 존재 여부 파악 가능 |
| 반복된 요청 탐지           | 크리덴셜 스터핑 또는 딕셔너리 공격일 수 있음      |

* 예시 : XML_PAIRS:/methodCall/methodName 경로에서 match: wp.getusersblogs`가 탐지되었다면, 
* 이는 공격자가 WordPress의 XML-RPC API를 이용해 이미 어떤 유효한 사용자 ID(아이디, 로그인 이름)를 알고 있을 가능성이 매우 높다.

---

## ✅ 대응 방안

1. **XML-RPC 비활성화** (사용하지 않는다면 강력 추천)

   ```apache
   <Files xmlrpc.php>
     Order Deny,Allow
     Deny from all
   </Files>
   ```

2. **WAF 차단**

   * 해당 요청 (`wp.getUsersBlogs`)을 **WAF에서 블랙리스트 처리**

3. **ID enumeration 방지**

   * `/author=1` 접근 시 리디렉션/403 처리
   * 사용자 프로필 노출 제한

---
