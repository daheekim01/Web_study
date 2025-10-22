## 📎 예제 1. ThinkPHP `invokefunction` POC (MD5 페이로드)

* **지금 형태는 '완전한 RCE 명령'은 아니고, `임의 함수 호출(POC)`**, 성공하면 **RCE로 악용 가능**함.

```
/?s=../\think\Container/invokefunction
&function=call_user_func_array
&vars[0]=md5
&vars[1][]=HelloThinkPHP
```

* 의도: 내부에서 `call_user_func_array('md5', ['HelloThinkPHP'])` 실행 유도 → 응답으로 MD5가 나오면 호출 성공.


## 완전한 RCE가 되려면 (필수 조건)

1. 공격자가 `vars[0]` 등으로 `system`, `exec`, `shell_exec`, `eval` 등을 지정할 수 있어야 함
2. 서버/프레임워크가 **함수명 검증(화이트리스트)** 또는 **disable_functions** 같은 보호를 하지 않을 것
3. 함수 실행 결과가 외부로 노출되거나 파일 쓰기/명령 실행이 가능할 것


## 불완전(실패) 조건 예시

* `invokefunction` 접근에 인증/권한 필요
* 함수 호출 시 화이트리스트 적용
* `disable_functions`로 위험 함수 비활성화
* WAF/필터가 요청 차단
* 호출 결과가 외부에 노출되지 않음


## 즉시 탐지/확인

* 요청 패턴 로그 검색

  ```bash
  # nginx/apache 액세스 로그에서 탐지
  grep -R "invokefunction" /var/log/nginx* /var/log/apache2* 
  grep -R "call_user_func_array" /var/log/nginx* /var/log/apache2*
  grep -R "vars%5B0%5D" /var/log/nginx* /var/log/apache2*
  ```
* POC 응답 직접 확인 (서버가 MD5 반환시)

  ```bash
  # 로컬에서 MD5 확인 (예: HelloThinkPHP)
  echo -n "HelloThinkPHP" | md5sum
  ```
* PHP 환경 확인

  ```bash
  php -r "echo ini_get('disable_functions').PHP_EOL;"
  php -r "echo ini_get('open_basedir').PHP_EOL;"
  ```

## 예방법

1. WAF/방화벽에서 아래 패턴 차단:

   * `think\Container/invokefunction`
   * `call_user_func_array`
   * `vars[0]=`, `vars[1]=` 등의 인자 전달 패턴
2. ThinkPHP 버전 즉시 패치(공식 패치 적용)
3. `disable_functions` 에 `system, exec, shell_exec, passthru, popen, proc_open, eval` 등 추가 검토
4. `open_basedir`/파일 권한 제한, 웹 프로세스 쓰기권한 최소화
5. 전체 포렌식(응답으로 POC 성공 시 필수)

---



