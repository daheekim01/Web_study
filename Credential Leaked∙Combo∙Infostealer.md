🔗 [관련 링크](https://www.zerodarkweb.kr/credential-leaked-combo-infostealer-%ED%95%B4%EC%BB%A4%EB%93%A4%EC%9D%B4-%EC%A0%95%EB%B3%B4%EB%A5%BC-%EC%88%98%EC%A7%91%ED%95%98%EB%8A%94-%EB%AF%B8%EB%AC%98%ED%95%9C-%EA%B8%B0%EC%88%A0%EB%93%A4/)


## 🔐 1. **Credential Leaked (크리덴셜 유출)**

### 📌 개념

* 특정 **서비스나 기업의 시스템이 해킹**되어, 사용자 계정 정보(ID, 비밀번호, 이메일 등)가 **직접적으로 유출된 상황**입니다.
* 흔히 말하는 "**데이터 침해(Breach)**"입니다.

### 🧪 기술적 설명

* 공격자는 SQL Injection, 취약한 인증 시스템, 서버 설정 오류 등을 통해 내부 DB에 접근합니다.
* 유출된 데이터는 `email:password`, `username:hash` 등의 형식으로 존재합니다.
* 일부는 해시(password hash)된 상태지만, 무차별 대입 공격(brute-force) 등으로 복호화되기도 합니다.

### 🎯 공격에 활용되는 방식

* 동일한 계정으로 타 서비스 로그인 시도 (Credential Stuffing)
* 이메일 기반 스피어 피싱
* 개인 맞춤형 사기 (예: 과거 주소, 전화번호 기반)

### 🛠 대표 사례

* **LinkedIn breach**
* **Adobe, Dropbox, T-Mobile** 등 대형 서비스 다수

---

## 📑 2. **Combolist (콤보 리스트)**

### 📌 개념

* 여러 출처에서 수집한 `ID:Password` 쌍을 **조합한 리스트**.
* **단일 침해 사건이 아니라**, 다수의 유출, Infostealer 로그 등을 합쳐 만든 \*\*“사용자 인증 정보 집합”\*\*입니다.

### 🧪 기술적 설명

* 콤보 리스트는 다음과 같은 형식으로 존재:

  ```
  user@example.com:123456
  testuser:password123
  ```
* 종종 대상 URL이 붙은 형태도 존재 (`ULP 형식`):

  ```
  https://example.com|user@example.com|password
  ```

### 🎯 공격에 활용되는 방식

* **Credential Stuffing 도구 (ex: Snipr, OpenBullet, SentryMBA)** 등에 입력되어 자동화된 로그인 시도 수행
* 대량의 계정 중 일부라도 로그인에 성공하면 → 계정 장악 → 추가 침투 (ex: MFA 우회, 내부망 접근 등)

### ⚠ 위협

* 한 번 유출된 비밀번호를 여러 사이트에 쓰는 **재사용 습관** 때문에 위험도가 매우 큼
* 공격자 입장에서 효율성과 ROI(Return on Investment, 투자수익률)가 뛰어난 기법

---

## 🦠 3. **Infostealer (정보 탈취 악성코드)**

### 📌 개념

* 사용자 기기에 침입하여 **저장된 로그인 정보, 브라우저 쿠키, 토큰, 인증서, 지갑 정보 등을 훔치는 악성코드**입니다.

### 🧪 기술적 설명

* 다양한 스틸러 종류: **RedLine, Raccoon, Vidar, Lumma, RisePro, Taurus** 등
* 탈취 대상:

  * 브라우저에 저장된 아이디/비번, 쿠키
  * 디스코드/텔레그램 토큰
  * 지갑(crypto wallet)
  * FTP, VPN, RDP 접속 정보
* 감염 방식:

  * 크랙 소프트웨어, 게임 치트, 피싱 사이트, 가짜 업데이트 설치 파일 등

### 🎯 공격에 활용되는 방식

* 탈취된 정보는 **자동으로 Telegram 등으로 공격자에게 전송**
* 이후 이 정보는 콤보 리스트로 가공되어 다시 공격에 재활용됨
* 일부는 실시간으로 다크웹 마켓에 등록되어 판매됨 (ex: Genesis Market, RussianMarket)

---

## 🔄 세 가지 요소의 연결 구조

```
[Infostealer]
  ↓ (개인 PC에서 정보 탈취)
[Credential Leaked]
  ↓ (개별 서비스에서 계정 유출)
[Combo List]
  ← 위 둘의 결과물이 모여 생성됨
  ↓
[Credential Stuffing 등 대규모 공격에 사용]
```

---

## 🔥 실전 공격 시나리오 예시

1. 사용자가 피싱 PDF 열고 RedLine Infostealer 감염
2. 저장된 로그인 정보와 쿠키가 공격자에게 전송
3. 공격자는 이 데이터를 `example.com|user@example.com|password123` 형식으로 가공
4. 수천\~수십만 개를 콤보 리스트로 만들어 판매 또는 사용
5. 자동화된 툴로 타 사이트에 로그인 시도 → 다단계 인증 회피, 추가 침투 시도

---

## 🛡️ 대응 방안 요약

| 유형                    | 대응 방법                                   |
| --------------------- | --------------------------------------- |
| **Credential Leaked** | 유출 감지 후 즉시 비밀번호 변경, 유출 모니터링             |
| **Combo**             | MFA 필수 적용, 동일 비밀번호 재사용 금지, IP 제한        |
| **Infostealer**       | EDR, 백신 소프트웨어, 사용자 보안 교육, 파일 다운로드 출처 검증 |

---

## 📚 참고

* [제로다크웹 원문 블로그 보기](https://www.zerodarkweb.kr/credential-leaked-combo-infostealer-%ED%95%B4%EC%BB%A4%EB%93%A4%EC%9D%B4-%EC%A0%95%EB%B3%B4%EB%A5%BC-%EC%88%98%EC%A7%91%ED%95%98%EB%8A%94-%EB%AF%B8%EB%AC%98%ED%95%9C-%EA%B8%B0%EC%88%A0%EB%93%A4/)
* [SpyCloud – Infostealer 연구](https://spycloud.com/blog/the-new-age-of-combolists)
* [Stealthmole – Combo List 분석](https://www.stealthmole.com/blog/combo-lists-the-criminals-key-for-cyber-attacks)
