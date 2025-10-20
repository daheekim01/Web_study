펜테스트 시 체크리스트 (실전 바로 사용)

(항목별 명령/방법 포함 — 안전하게 테스트 환경에서 실행)

식별 / 버전 확인

가능한 엔드포인트(브라우저)

/login_page.php, /login.php, /manage_overview_page.php, /bug_report_page.php, /view_all_bug_page.php

/api/soap/mantisconnect.php?wsdl 또는 /api/rest

파일/문서에서 버전 확인

CHANGELOG, README, mantisbt_version 등

HTTP 헤더 / HTML 주석 확인

curl -s -D - https://target/ | sed -n '1,40p'

curl -s https://target/ | grep -i mantis -n

인증·기본정보 점검

기본 계정 시도: admin/admin, administrator/administrator (주의: 운영 시스템에서 무차별 시도는 정책 위반)

사용자 등록/비밀번호 재설정 플로우 점검

XSS (Stored/Reflected)

이슈 생성/코멘트/프로필에 <script>alert(1)</script> 삽입 (격리된 테스트 환경에서)

탐지: 응답 HTML에서 스크립트가 그대로 반영되는지 확인

SQLi

파라미터에 ' OR 1=1 -- 같은 간단한 삽입으로 반응 확인

타임 기반 테스트(예: SLEEP(5) 또는 DBMS-specific 시간 함수)

자동화: sqlmap -u "https://target/view.php?id=1" --risk=2 --batch

파일 업로드

이미지 업로드 기능이 있으면 .php 파일을 업로드해 접근 시도

우회: <?php phpinfo(); ?>를 test.jpg로 업로드 후 GET으로 접근(실제 환경에선 매우 조심)

확인: 업로드 경로, 파일명 정규화, mime-type 검사, 실행 권한 확인

CSRF

이슈 생성/삭제 등 상태 변경 요청이 CSRF 토큰으로 보호되는지 확인(요청 재생)

API 검사

SOAP endpoint: curl "https://target/api/soap/mantisconnect.php?wsdl"

REST: 인증 없이 호출 가능한 엔드포인트가 있는지 확인

정보 노출

config_inc.php나 install.php 등이 웹상에 직접 노출돼 있는지 검색

curl -I https://target/config_inc.php (정책 확인 후)

권한/접근 제어

특정 사용자로 로그인 후 관리자 전용 페이지 접근 시도(권한 상승 취약점 점검)
