### 🎀 URI의 구성:

일반적으로 URI는 다음과 같은 형식으로 구성됩니다:

```
<스킴>://<호스트>/<경로>?<쿼리>#<프래그먼트>
```

예를 들어, `https://www.example.com:8080/path?query=1#fragment`

* **https**는 스킴
* \*\*[www.example.com\*\*은](http://www.example.com**은) 호스트
* **8080**은 포트
* **/path**는 경로
* **query=1**은 쿼리 파라미터
* **fragment**는 프래그먼트

**URI 스킴** (Uniform Resource Identifier Scheme)은 URI (Uniform Resource Identifier)의 한 부분으로, 리소스가 어떤 프로토콜을 사용해 접근되는지를 지정하는 역할을 합니다. URI는 웹 주소와 같은 자원의 위치를 나타내는데, 스킴은 이 자원에 접근하는 방법을 정의합니다.

예를 들어, URL(Uniform Resource Locator)은 URI의 일종이며, 그 안에서 스킴은 "http", "https", "ftp" 등으로 나타냅니다. 스킴은 리소스를 식별할 수 있는 방법을 알려주는 것이죠.

### URI 스킴의 예:

1. **http** – 웹 페이지를 요청할 때 사용하는 스킴 (예: `http://example.com`)
2. **https** – 보안된 웹 페이지 요청 시 사용하는 스킴 (예: `https://example.com`)
3. **ftp** – 파일 전송 프로토콜을 사용하여 파일을 접근할 때 사용하는 스킴 (예: `ftp://ftp.example.com`)
4. **mailto** – 이메일 주소를 나타낼 때 사용하는 스킴 (예: `mailto:user@example.com`)
5. **file** – 로컬 파일 시스템에서 파일을 접근할 때 사용하는 스킴 (예: `file:///C:/path/to/file`)

URI 스킴을 통해 리소스를 어떻게 접근할 수 있는지, 어떤 프로토콜이나 규칙을 사용해야 하는지 알려주기 때문에 웹에서 자원과의 상호작용에 중요한 역할을 합니다.
