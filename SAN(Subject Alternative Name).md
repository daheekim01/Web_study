
**"Can not find test.com neither in domains field nor in subject.common field."**

위 메시지는 **SSL/TLS 인증서 상의 도메인 정보가 실제 접속하려는 도메인과 일치하지 않아서 생기는 보안 문제**를 설명하고 있습니다.


🔍 **"Can not find test.com..."**

* 인증서 안에서 `test.com`이라는 도메인을 찾지 못했다는 말입니다.

🔍 **"...neither in domains field..."**

* 인증서의 **Subject Alternative Name (SAN)** 필드에 `test.com`이 없음

🔍 **"...nor in subject.common field."**

* 인증서의 **Common Name (CN)** 필드에도 `test.com`이 없음


## ✅ CN(Common Name) vs SAN(Subject Alternative Name)

| 항목             | **CN (Common Name)**                | **SAN (Subject Alternative Name)**                           |
| -------------- | ----------------------------------- | ------------------------------------------------------------ |
| 🔍 정의          | 인증서 소유자의 "주 도메인" 이름                 | 인증서에 포함된 **모든 허용 도메인 목록**                                    |
| 🧾 위치          | 인증서의 `Subject` 필드                   | `X.509 v3 Extension` 필드 중 하나                                 |
| 🎯 목적          | 원래는 **인증서의 주요 식별자**로 사용됨            | **여러 도메인** 또는 **서브도메인** 인증용으로 확장                             |
| 🛡️ 현재 브라우저 처리 | ✅ 일부 참고 (레거시 지원)                    | ✅ **표준이며, 반드시 검증 대상**                                        |
| 🌐 여러 도메인 인증   | ❌ 불가능 (1개 도메인만 가능)                  | ✅ 가능 (`example.com`, `www.example.com`, `api.example.com` 등) |
| 📜 표준화 여부      | 예전 방식 (Deprecated)                  | ✅ 현재 SSL/TLS 인증서에서 **공식 표준**                                 |
| 🔐 보안 권고사항     | 사용은 가능하나 **SAN 필드에 반드시 도메인 포함해야 함** | **브라우저는 SAN만 신뢰**하는 경우가 많음                                   |

---

### 🔐 1. SSL/TLS의 기본 역할

* SSL/TLS는 **클라이언트와 서버 간 통신을 암호화하고**,
  동시에 **서버의 정체(도메인)를 인증**하는 역할을 합니다.
* 이를 위해 **서버 인증서**는 **접속하려는 도메인**이 명시되어 있어야 합니다.

---

### 🧾 2. 인증서의 SAN 필드란?

* SAN (Subject Alternative Name)은 **인증서에 명시된 허용된 도메인 목록**입니다.
* 현대 브라우저는 **Common Name (CN)** 대신 **SAN 필드만 검사**합니다.
* 접속 도메인이 SAN 필드에 없으면 → \*\*"이 인증서는 해당 도메인을 인증하지 못한다"\*\*고 판단합니다.


## 🛡️ 왜 이게 SSL/TLS 취약점이 되는가?

SSL/TLS에서는 \*\*클라이언트(브라우저나 앱)\*\*가 서버에 접속할 때:

1. 서버가 \*\*자신의 인증서(Certificate)\*\*를 보냅니다.
2. 클라이언트는 이 인증서 안에 있는 도메인 정보(CN 또는 SAN)를 **현재 접속하려는 도메인과 비교**합니다.
3. 이 값이 **일치하지 않으면**, 인증서 위조 또는 스푸핑 위험이 있다고 판단하고 **경고 또는 연결 거부**합니다.

✅ **즉, 인증서에 `test.com`이 없다면 그 도메인을 보호하는 SSL 인증서가 아니기 때문에, 그걸 사용하면 SSL 보안상 "취약"한 상태**인 겁니다.

---

### 🚨 3. SAN에 `test.com`이 없을 때 문제 상황

| 항목     | 설명                                    |
| ------ | ------------------------------------- |
| 접속 도메인 | `https://test.com`                    |
| 서버 인증서 | SAN에 `test.com` 없음                    |
| 결과     | 브라우저 또는 클라이언트는 **이 인증서를 신뢰할 수 없음** 판단 |

---

### 🎯 4. MITM 공격자가 악용할 수 있는 시나리오

#### 공격 개요:

1. 사용자가 `https://test.com` 접속
2. MITM 공격자가 네트워크를 가로채 **자신의 가짜 인증서**를 전달
3. 서버 인증서에 `test.com`이 없거나 잘못되어 있는 경우
4. 사용자의 브라우저는 인증서를 신뢰하지 못하고 **경고** 또는 **연결 실패**
5. 그러나 사용자가 경고를 무시하거나, 클라이언트가 검증을 제대로 하지 않으면 → 공격 성공

#### 결과:

* 공격자는 사용자의 민감한 정보를 탈취 가능 (로그인 정보, 세션 쿠키 등)
* 사용자는 실제 서버가 아닌 **공격자의 서버에 연결된 상태**가 됨

---

### 🛡️ 올바른 인증서 예 (SAN 포함)

```
Subject: CN = test.com
Subject Alternative Name:
    DNS:test.com
    DNS:www.test.com
```

---

## 🔐 실제 예시

예를 들어:

* 사용자는 `https://test.com`에 접속
* 서버는 SSL 인증서를 보냄
* 그 인증서에 포함된 정보는:

```
Common Name (CN): www.example.com
Subject Alternative Name (SAN): www.example.com, api.example.com
```

🔴 여기서 **`test.com`이 없음**

---

## ✅ 요약 한 문장:

👉 **"SSL 인증서의 SAN 필드에 `test.com`이 없다면, 브라우저는 해당 인증서를 유효하지 않다고 판단하며, 이 틈을 노린 MITM 공격이 가능해진다."**

---

## 🛠️ 해결 방법

1. **도메인에 맞는 SSL 인증서를 새로 발급**받아야 합니다.

   * 인증서에 `test.com`이 포함되어야 함
   * 특히 **SAN 필드에 도메인들을 모두 명시**해야 함

2. 인증서 예시 (올바른 경우):

```
Common Name: test.com
Subject Alternative Name:
  - test.com
  - www.test.com
  - api.test.com
```

3. 인증서 확인 방법 (리눅스/OpenSSL):

```bash
openssl s_client -connect test.com:443 -servername test.com
```

→ 결과에서 `Subject`와 `Subject Alternative Name` 필드를 확인하세요.

---

## ✅ 요약

| 항목     | 설명                                 |
| ------ | ---------------------------------- |
| 에러 의미  | SSL 인증서 안에 `test.com`이라는 도메인이 없음   |
| 취약한 이유 | 접속 도메인과 인증서 정보가 불일치 → MITM 공격 위험   |
| 해결책    | 도메인에 맞는 올바른 인증서(SAN 포함)를 발급/적용해야 함 |

---
