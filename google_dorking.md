* https://www.xn--hy1b43d247a.com/initial-recon/osint/google-dorking
* 참고문서

## 웹 서비스의 디렉터리 경로에 접근할 경우 파일 리스트의 노출 유무
구글 도킹 예시: site:example.com(도메인) intitle:index of

* ① site : 특정 도메인이나 서브도메인에 한정해서 결과를 찾을 때 사용
'''
예시: site:*.example.com, site:www.example.com
'''

* ② intitle : 문서나 페이지 제목 내 단어 검색
'''
예시: intitle:login, intitle:vpn, intitle:authenticate
'''

* ③ filetype : 특정 파일 확장자를 가진 문서 검색
'''
예시: filetype:pdf, filetype:docx, filetype:hwp
'''

* ④ intext : 페이지 본문 내 특정 문자열 포함 여부 검색
'''
예시: intext:"Index of /admin", intext:"phpmyadmin"
'''

* ⑤ inurl : URL 경로나 도메인에 특정 단어 포함 여부 검색
'''
예시: inurl:s3.amazonaws.com, inurl:ftp, inurl:web.config
'''
