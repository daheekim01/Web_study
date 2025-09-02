`Content-Type: application/x-directory;`는 HTTP 응답 헤더에서 사용되는 **비표준 MIME 타입**으로, 응답 본문이 **"디렉토리 자체" 또는 디렉토리의 목록**이라는 것을 의미합니다.

---

## 🧱 **Apache, Nginx, 기타 웹 서버**에서
  **디렉토리 인덱싱(browsable directory listing)** 기능이 켜져 있을 때 사용됩니다.

  
<img width="1903" height="121" alt="image" src="https://github.com/user-attachments/assets/01bc3eb1-8648-461e-8fad-8d1f60496072" />
<img width="1894" height="651" alt="image" src="https://github.com/user-attachments/assets/c53ab060-b5c5-4c9a-913b-bf2bf80cfaa8" />


* 예를 들어 `/images/` 같은 디렉토리에 접근하면 보통 웹서버는 자동으로 index.html 파일을 찾아서 보여주는데, index.html 파일이 없고 Apache나 Nginx 같은 웹 서버에서 디렉토리 목록을 보여주도록 설정을 켜 두었다면 다렉토리 목록이 HTML 형식으로 생성되어 보여질 수도 있음

---

## 🧪 예시 응답 헤더

```http
HTTP/1.1 200 OK
Content-Type: application/x-directory
Content-Length: 1242
...
```

→ 이 경우, 본문은 HTML 형식의 디렉토리 목록일 수 있음 (`<a href="file.jpg">file.jpg</a>`)

---

## ⚠️ 보안 측면에서 주의할 점

| 위험요소               | 설명                                                  |
| ------------------ | --------------------------------------------------- |
| 🔓 **디렉토리 인덱싱 노출** | 이 타입이 응답에 나타났다는 건 서버가 **디렉토리 목록을 공개하고 있다는 뜻**일 수 있음 |
| 📂 **민감한 파일 노출**   | 잘못된 설정으로 인해 `.env`, `.git`, 백업 파일 등이 노출될 수 있음       |
| 🐞 **경로 추측 가능**    | 경로 구조가 노출되면, 공격자가 다른 숨겨진 파일을 추측하거나 접근 시도 가능         |


## ✅ 서버 측 보안 권장사항

| 항목     | 설정 예시              |
| ------ | ------------------ |
| Apache | `Options -Indexes` |
| Nginx  | `autoindex off;`   |
| IIS    | 디렉토리 검색 비활성화       |

---

## 🔥 공격 예시

### 📁 \[예시 1] 디렉토리 브라우징 통한 민감 파일 수집

#### 상황:

```
http://target.com/backups/
```

* 서버가 디렉토리 인덱싱을 허용 중
* 브라우저에서 접근 시 `.zip`, `.sql`, `.env`, `.bak` 파일 목록이 보임

#### 공격자가 하는 일:

* `.git/`, `.env`, `db.sql`, `config-old.php` 등 다운로드
* 다운로드한 `.sql` 파일에 DB 정보, 계정 정보 포함 → 다음 공격 (ex: DB 접근, 크리덴셜 리유즈 등)

---

### 🧪 \[예시 2] 자동화된 스캐너(봇) 공격

도구: `dirsearch`, `gobuster`, `feroxbuster`, `nikto`, Burp Suite Intruder 등

* URL 끝에 `/`, `/backup/`, `/admin/`, `/uploads/` 등 다양한 경로 자동 스캔
* 응답에서 `Content-Type: application/x-directory` 또는 `<title>Index of /path</title>` 감지
* 노출된 경로와 파일명 기반으로 공격 확장

---

### 🔄 \[예시 3] 경로 추측 공격(Path Traversal + Directory Indexing)

#### 예:

```
http://target.com/files/?file=../../
```

* 디렉토리 리스팅이 켜져 있다면, 이 경로로 내부 디렉토리 목록까지 열람 가능
* 이후 파일 다운로드 시도 → 시스템 내부 구조 노출 + 중요 파일 접근 가능

---

## 🔍 서버가 디렉토리 목록을 공개하고 있는지 알아내는 방법

### ✅ 방법 1: 수동 탐지 (브라우저에서 확인)

* URL에 `/`를 붙여서 접근:

  ```
  http://target.com/images/
  http://target.com/uploads/
  http://target.com/backup/
  ```
* 아래와 같은 HTML 응답이 오면 디렉토리 인덱싱이 켜져 있음:

```html
<title>Index of /uploads</title>
<h1>Index of /uploads</h1>
<hr>
<a href="file1.jpg">file1.jpg</a>
<a href="file2.zip">file2.zip</a>
```

* 또는 `Content-Type: application/x-directory` 헤더가 보일 수도 있음

---

### ✅ 방법 2: 자동화 도구 사용

#### 도구: `dirsearch`, `gobuster`, `nikto`, `feroxbuster`, `ffuf` 등

```bash
dirsearch -u http://target.com/
```

→ 디렉토리 인덱싱된 경로를 탐지하고 파일 목록까지 추출

---

### ✅ 방법 3: Burp Suite + Repeater

1. 브라우저로 `/images/` 같은 경로 접근
2. Burp에서 요청 캡처 후 응답 분석
3. 응답에 아래와 같은 요소가 있으면 디렉토리 인덱싱 활성화됨:

   * `Content-Type: application/x-directory`
   * `<title>Index of /</title>`
   * `<pre>` 태그로 파일 리스트
   * 파일명, 날짜, 크기 등 표 형식
  
---
