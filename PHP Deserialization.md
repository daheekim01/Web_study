## 🐈‍⬛ **PHP 객체 직렬화**에서 **Deserialization 취약점**을 활용한 공격 

* **역직렬화 취약점**: `unserialize()`가 **신뢰할 수 없는 사용자 입력을 처리할 때** 취약점이 발생할 수 있습니다. 이 공격 방식은 해당 취약점을 악용하여 악성 PHP 객체를 로드하고 이를 실행할 수 있게 만듭니다.
* **역직렬화된 객체가 악성 코드를 실행하거나 의도하지 않은 동작을 일으킬 수 있기 때문에 심각한 보안 위험을 초래할 수 있습니다.**
* **PHP 함수 호출**: `phpinfo()`와 같은 함수가 호출될 수 있고, 이는 서버에 대한 중요한 시스템 정보를 노출시킬 수 있습니다. 이 정보를 이용해 더 큰 공격을 시도할 수 있습니다.

---
### 페이로드 예시

```
controller\=SymfonyComponentYamlInline::parse&value\=!!php/object:a:1:{i:1;a:2:{i:0;O:32:\"MonologHandlerSyslogUdpHandler\":1:{s:9:\"*socket\";O:29:\"MonologHandlerBufferHandler\":7:{s:10:\"*handler\";O:29:\"MonologHandlerBufferHandler\":7:{s:10:\"*handler\";N;s:13:\"*bufferSize\";i:-1;s:9:\"*buffer\";a:1:{i:0;a:2:{i:0;s:2:\"-1\";s:5:\"level\";N;}}s:8:\"*level\";N;s:14:\"*initialized\";b:1;s:14:\"*bufferLimit\";i:-1;s:13:\"*processors\";a:2:{i:0;s:7:\"current\";i:1;s:7:\"phpinfo\";}}s:13:\"*bufferSize\";i:-1;s:9:\"*buffer\";a:1:{i:0;a:2:{i:0;i:-1;s:5:\"level\";N;}}s:8:\"*level\";N;s:14:\"*initialized\";b:1;s:14:\"*bufferLimit\";i:-1;s:13:\"*processors\";a:2:{i:0;s:7:\"current\";i:1;s:7:\"phpinfo\";}}}i:0;i:0;}}&exceptionOnInvalidType\=0&objectSupport\=1&objectForMap\=0&flags\777215&references\=1
```

---

### 전체 구조

요청은 URL-쿼리 형태로 보이며, 주요 파라미터는 `_controller` 와 `value` 입니다.
`_controller=SymfonyComponentYamlInline::parse` 로 보아 Symfony의 `Yaml\Inline::parse()`를 호출하는 맥락이고, `value=` 에는 `!!php/object:...` 형태의 **PHP 직렬화된(또는 PHP 객체 표기) 데이터**가 들어 있습니다. 이어서 `exceptionOnInvalidType=0`, `objectSupport=1` 등 파싱 옵션도 함께 전달되고 있습니다.
즉: **YAML 파서에게 PHP 객체 태그를 허용하라는 옵션과, 그 PHP 객체 데이터 자체를 넘기는 시도**입니다.

---

### `value` 안의 구문(토큰별 상세 분석)

```
!!php/object:a:1:{i:1;a:2:{i:0;O:32:"MonologHandlerSyslogUdpHandler":1:{s:9:"*socket" ; O:29:"MonologHandlerBufferHandler":7:{ ... } } i:0;i:0;}}
```


1. `!!php/object:`

   * YAML에서 **`!!php/object:`** 태그는 PHP 객체를 표현하려는 표기입니다. 일반적으로 Symfony YAML 컴포넌트에서 이 태그를 만나면 PHP 객체로 복원하려고 시도할 수 있습니다(단, `objectSupport` 옵션에 따라 허용/차단).

2. `a:1:{ ... }`

   * 이 부분은 **PHP 직렬화(serialized)** 표기에서의 배열(`a`) 혹은 객체 내부 구조를 가리키는 형태로 보입니다. 일반적인 PHP `serialize()` 출력과 유사한 문법을 사용합니다: `a:1:{ ... }`는 항목 1개인 배열입니다.

3. `i:1; a:2:{ ... }`

   * 인덱스가 정수 타입(`i`)인 배열 요소를 포함합니다. 내부에 또 다른 배열(길이 2)이 들어 있습니다.

4. `O:32:"MonologHandlerSyslogUdpHandler":1:{ ... }`

   * `O:<len>:"<ClassName>":<prop-count>:{ ... }` 형식 — **직렬화된 PHP 객체**.
   * 여기서는 `MonologHandlerSyslogUdpHandler` 라는 클래스(길이 32)가 1개의 프로퍼티를 가지고 있는 객체로 직렬화되어 있음이 표현됩니다.

5. `s:9:"*socket"; O:29:"MonologHandlerBufferHandler":7:{ ... }`

   * `s:9:"*socket"` 는 속성 이름(문자열). `*` 접두사는 직렬화 표기에서 주로 **프로텍티드/프라이빗 속성 표기**(문맥에 따라 달라지는 내부 표기)로 보입니다.
   * 이 속성의 값이 또 다른 객체(`MonologHandlerBufferHandler`)로 설정되어 있습니다(중첩 객체).

6. 내부 `MonologHandlerBufferHandler` 객체 구조

   * `s:10:"*handler"; O:29:"MonologHandlerBufferHandler":7:{ ... }` 처럼 **버퍼 핸들러가 또 다른 버퍼 핸들러를 가리키는 형태의 중첩**을 갖습니다.
   * 속성들: `*bufferSize` (정수 -1 등), `*buffer` (배열), `*bufferLimit`, `*processors`(배열) 등.
   * 중요한 부분: `*processors` 항목에 `i:1;s:7:"phpinfo";` 같은 항목이 있음 — **'phpinfo'라는 이름의 프로세서(콜러블)를 등록하려는 의도**가 보입니다.
  
   * 즉, `MonologHandlerSyslogUdpHandler`와 `MonologHandlerBufferHandler` 클래스들이 포함되어 있고, 그 속성들 중 `*socket`, `*handler`, `*buffer`와 같은 내부 변수들을 조작하고 있습니다.

7. 끝부분 `i:0;i:0;` 등

   * 직렬화 배열의 다른 인덱스가 있는 것처럼 보이지만 구조가 반복적/중첩적으로 끝나는 형태입니다. 전체적으로는 **여러 중첩 객체와 배열**로 구성된 직렬화된 데이터입니다.

---

### 이 공격의 작동 원리:

1. **PHP 객체 직렬화 공격**: `!!php/object:`로 시작하는 직렬화된 객체는 PHP의 `unserialize()` 함수에서 역직렬화될 수 있습니다.
2. **클래스 로딩 및 메서드 호출**: 공격자는 직렬화된 데이터를 통해 PHP 클래스나 메서드를 호출하고, 예를 들어 `phpinfo()`와 같은 민감한 함수나 시스템 정보를 출력할 수 있습니다.
3. **MonologHandler 클래스**: `Monolog` 라이브러리를 이용한 공격일 가능성이 있으며, 로깅 시스템을 악용하여 로그에 민감한 정보를 기록하거나, 네트워크를 통해 외부 서버에 데이터를 유출할 수도 있습니다.

* `_controller` 파라미터를 통해 `Symfony\Component\Yaml\Inline::parse` 메서드를 호출하면서, 복잡한 **PHP 객체 직렬화된 데이터**를 전달하고 있습니다.
* `value` 파라미터에 전달된 **직렬화된 PHP 객체**가 의도된 클래스를 로드하고 특정 동작을 수행할 수 있도록 조작된 부분입니다.
* `phpinfo()`라는 함수가 처리 과정에서 **프로세서**로 지정되어 있어, 이 객체가 역직렬화된 후 `phpinfo()`를 호출하게 될 가능성이 높습니다. `phpinfo()`는 PHP 설정 정보를 출력하는 함수로, 공격자가 시스템 정보에 접근할 수 있게 됩니다.

---

### **PHP 객체 직렬화 취약성(POP/POI — PHP Object Injection)** 악용

**PHP 직렬화(serialized object)** 포맷 예시 코드는 다음과 같습니다. 

```
O:10:\"PMA_Config\":1:{s:6:\"source\",s:11:\"/etc/passwd\";}
```

* `O:10:"PMA_Config":1:{...}`은 클래스 `PMA_Config`(길이 10)의 인스턴스를 직렬화한 표현이며, 내부 속성 `source`에 `"/etc/passwd"`를 넣으려는 시도입니다.
* 애플리케이션이 외부 입력(POST/쿠키 등)을 그대로 `unserialize()`하면, 마법 메소드(`__wakeup`, `__destruct`, 기타 gadget 메소드를 가진 클래스)가 실행되어 파일 읽기/원격 코드 실행/파일 포함 등으로 이어질 수 있습니다.
* `PMA_Config`는 phpMyAdmin 관련 클래스 이름으로, 과거 phpMyAdmin의 특정 버전·환경에서 직렬화된 객체로 파일 시스템 접근/불러오기에 이용되던 사례가 존재합니다. 여기서는 `source="/etc/passwd"`로 **로컬 파일 읽기(LFI/LFR)** 를 시도하는 전형적인 페이로드입니다.
