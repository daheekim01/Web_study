# 네트워크 및 IT 용어 정리 (based on vendor's Datasheets)

## 기기 및 네트워크 장비

### ● 액세스 포인트 (AP)

무선 장치들이 네트워크에 연결할 수 있도록 해주는 장비. Wi-Fi 신호를 제공함.

### ● SFP (Small Form-Factor Pluggable)

광섬유 및 이더넷 케이블을 연결하기 위한 모듈형 포트로, 데이터 전송 및 신호 변환에 사용됨. 주로 신호 ​​변환 및 데이터 전송에 사용된다.

### ● 업링크 포트

스위치와 라우터 또는 상위 네트워크 장비를 연결하는 포트. 상위 계층 네트워크로 트래픽을 전달함.

### ● Netscaler

시트릭스(Citrix)에서 제공하는 애플리케이션 전송 제어 장치로, 로드 밸런싱, 웹 애플리케이션 방화벽, 트래픽 최적화 기능 제공.

### ● 슈퍼바이저 엔진 (Supervisor Engine)

고급 네트워크 스위치(특히 Cisco)에서 네트워크 제어 및 관리를 담당하는 주요 제어 모듈.

---

## 네트워크 기술 및 개념

### ● BYOD (Bring Your Own Device)

직원들이 개인 소유의 장치를 회사 네트워크에 연결해 업무에 활용하는 개념.
🔗 [관련 링크](https://www.fortinet.com/kr/resources/cyberglossary/byod)

### ● QoS (Quality of Service)

네트워크 트래픽에 우선순위를 부여해 특정 애플리케이션이나 데이터 흐름의 성능을 보장하는 기술. 

### ● MU-MIMO (Multi-User Multiple Input Multiple Output 다중 사용자 다중 입출력)

하나의 Wi-Fi 액세스 포인트(AP)가 여러 장치에 동시에 데이터를 전송할 수 있도록 하여 네트워크 용량과 효율성을 높이는 무선 통신 기술. 장치 밀도가 높은 환경에서 여러 장치의 동시 통신을 가능하게 하여 효율성을 증가하고, 전체 네트워크의 성능을 향상.
AP가 여러 개의 데이터 스트림을 생성하고, 각 스트림을 분리된 공간으로 전송하여 여러 장치가 주파수 자원을 동시에 사용하여 데이터를 주고받음. 

### ● PoE (Power over Ethernet) / PoE+

네트워크 케이블을 통해 전력과 데이터를 동시에 공급하는 기술. PoE+는 더 높은 전력을 지원함.
🔗 [관련 링크](https://ko.itpedia.nl/2022/04/10/power-over-ethernet-poe-vs-poe-vs-poe-levert-geld-op/)

### ● UPOE (Universal Power over Ethernet)

Cisco가 제안한 표준으로, 최대 60W의 전력을 공급할 수 있는 PoE의 확장 기술.

### ● 제로 터치 프로비저닝 (ZTP)

디바이스 초기 설정을 자동화하여 수동 개입 없이 구성하는 기술. 처음 시작할 때 구성 파일을 디바이스에 직접 전달하여 네트워크 디바이스를 일관되고 동시에 자동화된 방식으로 구성 가능.
🔗 [관련 링크](https://www.checkpoint.com/kr/cyber-hub/network-security/what-is-zero-trust/what-is-zero-touch-provisioning-ztp/)

### ● MTBF (Mean Time Between Failures)

시스템이나 장비의 평균 고장 간격. 신뢰성 평가 지표로 사용됨.

### ● UADP (Unified Access Data Plane)

Cisco에서 사용하는 데이터 플레인 아키텍처로, 유무선 통합 처리를 지원함.

### ● ASIC (Application Specific Integrated Circuit)

특정 용도에 최적화되어 설계된 반도체 칩(집적 회로). 고속 처리와 저전력 설계에 강점을 가짐.

### ● 폼팩터 (Form Factor)

장비나 부품의 물리적 크기, 모양, 레이아웃 규격을 의미. 예: 서버 폼팩터, 메모리 폼팩터 등.

### ● 기가비트 이더넷

초당 1Gbps의 속도로 데이터를 전송하는 이더넷 표준.

### ● GBIC (Gigabit Interface Converter)

기가비트 이더넷에서 광신호와 전기 신호 간 변환을 위한 모듈. SFP보다 구형.

### ● 무선 액세스 포인트(AP)와 에어 모니터(AM)

* **AP**: 사용자 단말에 무선 인터넷 제공.
* **AM**: 무선 스펙트럼을 모니터링하여 보안 및 장애 탐지.

### ● 터널링

한 네트워크 프로토콜의 데이터를 다른 프로토콜로 캡슐화하여 전송하는 기술. VPN 등에 사용됨.

### ● WLAN (Wireless LAN)

무선으로 연결된 로컬 네트워크. Wi-Fi가 대표적 기술.

### ● 인텐트 기반 네트워킹 (IBN)

사용자의 의도를 네트워크 정책으로 해석해 자동으로 적용하고 네트워크 서비스를 효율적으로 제공하는 네트워크 관리 방식.

### ● MLD Snooping (Multicast Listener Discovery)

IPv6 멀티캐스트 트래픽을 스위치가 효율적으로 전달하도록 도와주는 기능.

### ● 페일오버 (Failover)

시스템 장애 발생 시 자동으로 예비 시스템으로 전환되어 가용성을 유지하는 메커니즘.컴퓨터 시스템, 서버, 네트워크 등에서 주 시스템에 장애가 발생했을 때, 장애 조치를 위해 예비 시스템으로 자동으로 전환되어 서비스 중단을 막고 가용성을 유지하는 기능. 이는 고가용성(HA)을 달성하기 위한 중요한 메커니즘이며, 사람이 수동으로 전환하는 스위치오버(Switchover)와는 달리, 장애 발생 시 자동으로 전환이 이루어짐. 

---

## 네트워크 구성 및 프로토콜

### ● VLAN 스패닝 트리 및 고속 스패닝 트리 (PVSTP / PVRSTP)

* **STP (Spanning Tree Protocol)**: 루프 방지를 위한 프로토콜.
* **PVSTP (Per-VLAN STP)**: VLAN 별로 독립적인 STP 실행.
* **PVRSTP (Per-VLAN Rapid STP)**: 고속 수렴을 지원하는 VLAN 단위의 STP.

### ● OSPF (Open Shortest Path First)

링크 상태 기반의 내부 라우팅 프로토콜로, 빠른 수렴 속도와 대규모 네트워크에 적합함.

### ● 백홀 (Backhaul)

네트워크의 중앙 장비와 지역 장비를 연결하는 핵심 전송 구간. 예: 기지국과 코어 네트워크 연결.

### ● 메시 네트워크 (Mesh Network)

모든 노드가 서로 직접 또는 간접 연결되어 데이터를 전달하는 구조. 안정성과 확장성이 높음.

---

## 제품 회사들

* Cisco, Citrix, Dell technology, Netgear, foredge, HP, HPE, Huawei, Ruckus, 엔트로링크, 파이오링크 등 

