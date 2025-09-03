# 🌐 DNS (Domain Name System)

## 네임서버(NS) + CNAME 레코드

---

## 1. 네임서버 (NS: Name Server)

* 도메인의 **DNS 정보를 보관하고 응답해주는 서버**
* 각 도메인이 어떤 DNS 서버를 사용해야 하는지를 지정함
* 사용자가 웹사이트에 접속할 때, 어떤 DNS 서버에서 해당 도메인의 IP 주소를 확인할지 알려줌

### 예시

```dns
example.com.     IN     NS     ns1.exampledns.com.
example.com.     IN     NS     ns2.exampledns.com.
```

## ✅ **네임서버가 도메인 이름만 있고, IP 주소가 등록되지 않은 경우**

* 네임서버(NS)는 \*\*이름(name)\*\*만 등록되어 있고, 해당 이름이 \*\*A 레코드(IP 주소)\*\*로 변환되지 않는 경우가 있다.
* 보통 NS 레코드는 다음과 같이 구성:

```
도메인: example.com
NS: ns1.exampledns.com
```

하지만 `ns1.exampledns.com` 자체가 A 레코드를 가지고 있지 않으면 IP를 확인할 수 없다.

---

| 개념                  | 설명                                                                                  |
| ------------------- | ----------------------------------------------------------------------------------- |
| **Glue Record**     | 네임서버가 도메인 내부에 있을 때, **IP 주소를 함께 등록**해줘야 함 (`ns1.example.com` 등)                     |
| **.kr vs 기타 TLD**   | `.kr` 도메인은 KISA 정책으로 네임서버 IP가 **공개되는 경우가 많음**, 반면 기타 TLD(Top-Level Domain) 예: .com, .net, .org, 등은 IP가 보이지 않을 수 있음.  |
| **IP 주소가 안 보이는 이유** | glue record 미등록, 개인정보 보호 정책(GDPR), DNS 설정 누락 등이 원인일 수 있음                            |

---

## 2. CNAME 레코드 (Canonical Name Record)

* 도메인 이름이 **다른 도메인 이름을 가리키도록** 설정하는 레코드
* 즉, **도메인의 별명(alias)** 기능

### 예시

```dns
www.example.com.    IN    CNAME    example.com.
```

* 의미: `www.example.com`은 `example.com`을 가리킴 → `example.com`의 A 레코드(IP)를 따름

### ✅ 순서

1. 사용자가 `www.example.com` 접속
2. DNS는 CNAME을 확인 → `example.com`로 리다이렉트
3. `example.com`의 A 레코드를 찾아 IP 주소 반환

---

## ⚠️ 주의사항 

| 항목                       | 설명                                                               |
| ------------------------ | ---------------------------------------------------------------- |
| **CNAME은 단독 사용만 가능**     | CNAME 레코드를 사용하는 도메인에는 **A, MX, TXT** 등을 함께 설정할 수 없음              |
| **루트 도메인에는 CNAME 사용 불가** | 예: `example.com`에는 CNAME 설정 불가능 (`www.example.com`에는 가능)         |
| **Glue Record 필요 조건**    | 네임서버가 도메인 내부에 있을 경우(예: `ns1.example.com`) → A 레코드(IP)도 함께 등록해야 함 |

---

## 🔄 A 레코드 vs CNAME 레코드 vs NS 레코드

| 구분         | 가리키는 대상   | 예시                                 | 주요 용도               |
| ---------- | --------- | ---------------------------------- | ------------------- |
| **A 레코드**  | IP 주소     | `example.com → 123.123.123.123`    | 도메인을 IP에 직접 연결      |
| **CNAME**  | 다른 도메인 이름 | `www.example.com → example.com`    | 도메인의 별명(alias) 설정   |
| **NS 레코드** | 네임서버 주소   | `example.com → ns1.exampledns.com` | 도메인이 사용하는 DNS 서버 지정 |

---


