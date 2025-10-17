# 🚀 PHP Filter Chain 

💡 **PHP Filter Chain**은 PHP의 *Wrapper*와 *Conversion Filter* 기능을 연속으로 사용해서
서버 내에서 원하는 임의의 문자열, 코드 조각을 만들어내는 공격 기법.

* CTF나 실제 공격에서 LFI(Local File Inclusion) 취약점이 있을 때
* 보통 ".php" 파일만 인클루드 가능하게 제한돼 있어서 임의 코드 실행이 어려워
* 이때 PHP Filter Chain을 사용하면 필터를 연속 적용해 원하는 코드를 만들어서 **원격 코드 실행(RCE)**까지 사용 가능 (LFI2RCE)

---

### 핵심 요소 ✨

#### ① PHP Wrappers (PHP의 URL 프로토콜)

* 파일, HTTP, 데이터 등 다양한 자원에 접근할 수 있게 해줌
* 대표적인 것들:

  * `file://` (파일)
  * `php://` (PHP I/O)
  * `php://filter` (필터 적용)
  * `php://temp` / `php://memory` (임시 메모리)
  * 그 외에도 data:, convert., phar:// 등의 필터/래퍼 문자열이 존재

#### ② Conversion Filters (문자셋 변환 필터)

* 문자열을 다양한 문자 인코딩으로 변환해줌
* 여러 필터를 **파이프라인(`|`)**으로 이어붙여서 다단계 변환 가능
* 예) `convert.base64-encode`, `convert.base64-decode`, `convert.iconv.*` 등

```text
php://filter/
convert.iconv.UTF8.CSISO2022KR |
convert.iconv.CP1256.UTF32 |
convert.base64-encode |
convert.iconv.UTF8.UTF7 |
convert.base64-decode /resource=php://temp
```
---

### 어떻게 동작할까? 🔄

> 기본 아이디어:
> **빈 문자열(php://temp)을 여러 문자셋 변환 필터를 거치면서 특정 바이트 시퀀스(문자)를 '조립'한다!**

* 예를 들어, 빈 문자열을 `UTF8 → CSISO2022KR` 변환 시, 특정 이스케이프 시퀀스(`1b 24 29 43`)가 붙음
* 이걸 활용해 문자열을 조작하며 원하는 문자를 하나씩 만들어내는 거야!

---

### 실제 예시 🛠️

```text
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP1154.UCS4/resource=php://temp
```

* 빈 문자열(`php://temp`) → `UTF8`에서 `CSISO2022KR`로 변환 →
* `CP1154`에서 `UCS4`로 변환 →
* 최종적으로 "S" 문자(0x53)가 포함된 문자열 완성!


#### 한계점 & 해결책 💡

* 필터 변환 과정에서 **불필요한 바이트**(노이즈)가 생김
* 단순히 변환만으로는 원하는 PHP 코드 조각 만들기 어려움


* `base64` 인코딩/디코딩 필터를 추가해 노이즈를 걸러내고 필요한 문자만 남김
* 예를 들면:

  * `convert.base64-encode` → `convert.base64-decode` 연속 사용
* 이렇게 하면 `[a-zA-Z0-9+/=]` 범위 내의 깨끗한 문자열만 얻을 수 있어!


#### LFI2RCE 🎯

원하는 문자열, 예를 들어:

```php
<?php system($_GET['cmd']) ?>
```

이걸 필터 체인으로 만들어서 LFI 취약점에 끼워 넣으면,

**원격 명령어 실행(RCE)** 달성 가능! 😱

---

### Payload 구조 (예시)

```text
php://convert.iconv.UTF8.CSISO2022KR|
convert.base64-encode|
convert.iconv.UTF8.UTF7|
... (복잡한 문자셋 변환 그룹) ...
convert.base64-decode/resource=php://temp
```

* 빈 문자열을 여러 문자셋 변환과 base64 필터를 거쳐서
* 최종적으로 원하는 PHP 코드의 base64 인코딩 문자열을 만들어 냄

---

### 9️⃣ 요약 정리 🎉

| 단계            | 설명                            | 예시 필터                           |                            |
| ------------- | ----------------------------- | ------------------------------- | -------------------------- |
| **원본 문자열 고정** | `php://temp` 빈 문자열 사용         | `php://temp`                    |                            |
| **문자열 변환**    | 여러 문자셋 변환을 통해 원하는 문자 조립       | `convert.iconv.UTF8.CSISO2022KR | convert.iconv.CP1154.UCS4` |
| **노이즈 제거**    | base64 인코딩 & 디코딩으로 깔끔한 문자열 획득 | `convert.base64-encode          | convert.base64-decode`     |
| **최종 문자열 획득** | 원하는 PHP 코드(base64로 인코딩된 상태)   | 복잡한 필터 체인 조합                    |                            |

---

### 🔥 꿀팁

* 이 공격기법은 **리눅스 환경**에서 더 잘 동작!
* 윈도우에서는 문자셋 지원 문제로 정상 동작 안 할 수 있음
* 자동화 스크립트(예: [php_filter_chain_generator.py](https://github.com/synacktiv/php_filter_chain_generator)) 활용하면 편리

---

### 참고 자료 📚

🔗 {[https://www.dottak.me/1964af8a-50ca-800b-9c3f-da340bfa9b5d]}
🔗 {[https://www.dottak.me/1964af8a-50ca-800b-9c3f-da340bfa9b5d](https://y0un.tistory.com/62)}

* [PHP Wrappers 공식문서](https://www.php.net/manual/en/wrappers.php)
* [PHP Filters 공식문서](https://www.php.net/manual/en/filters.convert.php)
* [synacktiv PHP filter chain](https://github.com/synacktiv/php_filter_chain_generator)
* [HackTricks LFI2RCE](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters)

