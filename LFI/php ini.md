
## 🧩 `php.ini` — **PHP 전역 설정 파일**

### 🔓 노출 시 취약점

| 항목                                               | 위험성                                          |
| ------------------------------------------------ | -------------------------------------------- |
| `display_errors = On`                            | 에러 메시지에 파일 경로, 변수 값 등 민감 정보 출력               |
| `expose_php = On`                                | PHP 버전 노출 → 버전 기반 취약점 공격 가능                  |
| `allow_url_fopen = On`, `allow_url_include = On` | RFI(원격 파일 포함) 취약점 가능성 증가                     |
| `disable_functions` 미설정                          | `exec`, `shell_exec`, `system` 등 위험 함수 사용 가능 |

### ✅ 방지책

* 운영 환경에서는 반드시:

  ```ini
  display_errors = Off
  expose_php = Off
  allow_url_include = Off
  disable_functions = exec,passthru,shell_exec,system
  ```
* `php.ini` 파일은 외부에서 직접 접근되지 않도록 웹서버에서 차단
* 설정 내용이 유출되었을 경우, 서버 구성 파악 및 취약점 매핑에 악용됨

---

## 🚨 공통 대응 방안

| 항목                  | 설명                                                        |
| ------------------- | --------------------------------------------------------- |
| 웹 루트 파일 보호          | `.ht*`, `*.ini`, `*.cnf`, `*.yml`, `*.env` 등은 직접 접근 차단 필요 |
| 웹 서버 설정 예시 (Apache) |                                                           |

```apache
<FilesMatch "\.(ini|cnf|yml|env|git|htaccess)$">
  Require all denied
</FilesMatch>
```

\| 웹 서버 설정 예시 (Nginx) |

```nginx
location ~* \.(ini|cnf|yml|env|git)$ {
  deny all;
}
```

---
