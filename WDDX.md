# 🔭 WDDX와 ColdFusion, 직렬화/디시리얼라이즈란?
 
### 직렬화(Serialization) / 디시리얼라이즈(Deserialization) — 핵심 개념

* **직렬화**: 프로그램 내부의 데이터(배열, 객체, 구조체 등)를 문자열 형태(일반적으로 바이트 시퀀스)로 바꾸는 것. 네트워크 전송이나 파일 저장을 위해 사용한다.
  예: `{"name":"alice","age":30}` 처럼 객체를 문자열로 변환.
* **디시리얼라이즈**: 직렬화된 문자열을 원래의 데이터(객체)로 복원하는 것.
  문제는: **외부에서 전달된 문자열을 그대로 신뢰해 복원하면 위험**할 수 있음.

### WDDX란?

* **WDDX**는 XML 기반의 직렬화 포맷(구조화된 데이터를 XML로 표현한 것)입니다. ColdFusion에서 과거에 널리 쓰였다.
* 예: 배열이나 구조체를 `<wddxPacket>…</wddxPacket>` 형태의 XML로 표현.

### ColdFusion(Adobe ColdFusion)이란?

* 서버 사이드 애플리케이션 플랫폼(언어/서버). 웹 애플리케이션을 동작시키는 프레임워크/런타임을 제공합니다.
* ColdFusion은 내부적으로 **태그(tag)** 기반 또는 객체를 통해 파일 접근, 캐시 조작, 명령 실행 등 다양한 기능을 제공.

### 🤧 직렬화/디시리얼라이즈 취약점 원리

* 공격자가 조작한 직렬화 데이터(예: WDDX)를 서버에 보내면, 서버가 그 데이터를 **검증 없이 디시리얼라이즈**하여 내부 객체(예: 특정 클래스/태그 인스턴스)를 생성할 수 있음.
* 생성되는 객체나 태그가 가진 속성(property)을 조작하면 **파일 읽기/쓰기, 시스템 명령 실행, 민감 정보 노출** 등으로 이어질 수 있음.
* 요약: **"외부 입력 → 디시리얼라이즈 → 내부 객체/동작 생성"** 과정에서 검증이 없으면 공격자가 악의적 동작을 유도할 수 있음.


# 🔮 공격 흐름

1. 공격자: 조작된 WDDX XML(혹은 다른 직렬화 포맷)을 만든다. (어떤 클래스/태그와 속성 값을 지정)
2. 공격자: 이 WDDX를 애플리케이션의 입력 파라미터(예: `argumentCollection=`)로 전송.
3. 애플리케이션: 수신한 WDDX를 디시리얼라이즈하여 내부 객체를 복원(또는 태그 실행)함.
4. 복원된 객체/태그의 동작(파일 접근, 명령 실행 등)이 수행되어 **정보 노출·파일 변경·원격코드실행(RCE)** 등이 발생할 수 있음.

# 🪄 실제 예시 페이로드 

```
argumentCollection=<wddxPacket version='1.0'><header/><data>
  <struct type='acoldfusion.tagext.io.cache.CacheTaga'>
    <var name='directory'><string>C:Windows</string></var>
  </struct>
</data></wddxPacket>
```


1. `argumentCollection=`: 애플리케이션이 이 파라미터에서 WDDX 데이터를 읽도록 의도.
2. `<wddxPacket>…</wddxPacket>`: WDDX 포맷의 직렬화 블록.
3. `<struct type='acoldfusion.tagext.io.cache.CacheTaga'>`: 디시리얼라이즈 시 **`acoldfusion.tagext.io.cache.CacheTaga`** 라는 타입(ColdFusion 내부의 특정 태그/클래스)을 생성하도록 지정.
4. `<var name='directory'><string>C:Windows</string></var>`: 그 객체의 `directory` 속성을 `C:Windows`로 설정하려 시도 — 즉 서버의 `C:\Windows` 디렉터리를 가리키게 함.

* 공격자는 해당 태그(또는 클래스)의 동작을 악용해 **서버 파일 접근(읽기/캐시 조작 등)** 혹은 그 태그가 가진 기능을 통해 추가 악용(파일 생성, 명령 실행 등)을 하려는 가능성이 큼.

#  취약점/악용 여부 판단 포인트

* 애플리케이션이 외부 WDDX를 **디시리얼라이즈**하는가?
* `acoldfusion.tagext.io.cache.CacheTaga` 타입을 내부에서 생성/처리하는가?
* 해당 태그가 파일 시스템 접근 또는 다른 민감한 동작을 수행하는가?
* 입력 검증(화이트리스트)이나 WAF가 이 요청을 차단하는가?
* ColdFusion 버전에 알려진 WDDX 디시리얼라이즈 취약점(CVE 등)이 있는가?

#  간단한 탐지/검증 방법(비파괴적)

* 웹서버 로그에서 패턴 검색:

  ```bash
  grep -R "wddxPacket" /var/log/nginx* /var/log/apache2* /path/to/app/logs
  grep -R "argumentCollection=" /var/log/*
  ```
* ColdFusion 로그(예: application/exceptions)에서 예외/비정상 이벤트 확인
* 파일시스템 검사: `C:\Windows`에 비정상적 파일 생성 여부(윈도우 서버라면 이벤트 로그 확인)
* **주의:** 실제로 페이로드를 재전송해 실험(파일 읽기/명령 실행 등)하지 마세요 — 파괴적 결과 초래 가능.

