# ARIA Implementation

ARIA(KS X 1213-1, RFC 5794) 블록 암호 알고리즘을 C로 직접 구현한 프로젝트입니다.

## 개요

ARIA는 학계(Academy), 연구소(Research Institute), 정부 기관(Agency)이 공동으로 개발한 대한민국 표준 블록 암호로, 2004년 KS X 1213-1로 제정되었습니다. 국가·공공기관이 도입하는 검증필 암호모듈의 검증 대상 블록암호(ARIA, SEED, LEA, HIGHT) 중 하나입니다. 미국 표준 블록 암호인 AES와 같은 SPN 계열이면서도, 암호화와 복호화에 동일한 라운드 연산 구조를 재사용할 수 있는 ISPN(Involutional SPN) 구조를 채택한 점이 특징입니다. 국가·공공기관 암호모듈 검증 대상인 국내 표준 블록 암호이고, 공개된 표준 문서와 테스트 벡터로 구현 결과를 직접 검증할 수 있어 ARIA를 선택했습니다.

- **알고리즘**: ARIA (ISPN, Involutional SPN 구조)
- **지원 키 길이**: 128/192/256비트
- **블록 크기**: 128비트
- **언어**: C
- **개발 환경**: Visual Studio

## 참조 문서

- KS X 1213-1 (국가표준인증 e나라표준인증)
- RFC 5794 (A Description of the ARIA Encryption Algorithm)

## 파일 구성

| 파일 | 내용 |
| --- | ---|
| aria.h | 파일 간 공유 인터페이스 선언 (S-box, 확산 계층 상수, 라운드 함수, 키 스케줄, 암/복호화 함수) |
| aria_tables.c | S-box(S1~S4), 확산 계층 행렬 A, 키 확장용 라운드 상수 CK 정의 |
| aria_core.c | 치환 계층(SL1, SL2), 확산 계층(diffusion), 라운드 함수(FO/FE), 키 확장(keyExpansion), 128비트 순환 이동(ROT) 구현 |
| aria_cipher.c | 블록 단위 암호화/복호화 본체(`ARIA_encrypt`, `ARIA_decrypt`) |
| aria_test_encrypt.c | RFC 5794 Appendix A 테스트 벡터로 암호화 검증 |
| aria_test_decrypt.c | 동일 테스트 벡터로 복호화 검증 |

## 구현 특징

- **확산 계층 최적화**: 16x16 행렬과의 직접 곱셈 대신, KS X 1213-1 부속서 C.2의 8비트 단위 구현 방법에 따라 공통 XOR 항(`T0~T3`, `U0~U7`)을 재사용해 연산 횟수를 96회에서 52회로 줄였습니다.
- **키 확장**: 3라운드 Feistel 구조로 W0~W3을 계산한 뒤 라운드 키를 생성하며, 복호화용 라운드 키(dk)는 암호화용 라운드 키(ek)를 역순 배치하고 중간 라운드에 diffusion을 적용해 도출합니다.

## 범위 및 제약사항

- 16바이트(128비트) 단일 블록 암호화/복호화만 지원합니다.
- CBC, CTR 등 운영 모드는 구현되어 있지 않습니다.
- 데이터 길이를 16바이트의 배수로 맞추는 패딩(padding) 처리는 포함되어 있지 않습니다.

## 예외 처리

- `keyExpansion`은 키 길이가 16/24/32바이트가 아니면 `ks->rounds=0`으로 실패를 알리고 종료합니다.
- `key` 또는 `ks`가 NULL이면 키 확장을 하지 않고 종료합니다.
- 호출하는 쪽은 `keyExpansion` 뒤에 `ks.rounds == 0` 인지 확인해야 합니다.

## 사용 방법

테스트 파일(`aria_test_encrypt.c`, `aria_test_decrypt.c`)의 `main` 함수 맨 위 배열에 테스트 벡터를 입력해서 실행합니다.<br>
호출 순서(`keyExpansion` → `ARIA_encrypt` 또는 `ARIA_decrypt`)도 이 파일에서 확인할 수 있습니다.

**aria_test_encrypt.c**

| 변수 | 크기 | 입력할 값 |
|---|---|---|
| `key[]` | 16/24/32바이트 | 128/192/256비트 키 |
| `plaintext[16]` | 16바이트 | 평문 |
| `expected[16]` | 16바이트 | RFC 5794의 기대 암호문 |

**aria_test_decrypt.c**

| 변수 | 크기 | 입력할 값 |
|---|---|---|
| `key[]` | 16/24/32바이트 | 128/192/256비트 키 |
| `ciphertext[16]` | 16바이트 | 암호문 |
| `expected[16]` | 16바이트 | RFC 5794의 기대 평문 |

입력할 테스트 벡터는 아래 '검증' 섹션을 참고하세요.

## 검증

RFC 5794 Appendix A의 KAT(Known Answer Test) 벡터를 이용해 암호화/복호화 결과를 검증합니다.<br>
Appendix A.1(128비트), A.2(192비트), A.3(256비트) 벡터를 각각 사용했고, 저장소의 테스트 파일에는 A.3(256비트) 벡터가 들어 있습니다.

- `aria_test_encrypt.c`: 평문을 `ARIA_encrypt`로 암호화한 결과를 RFC 기대 암호문과 비교
- `aria_test_decrypt.c`: 암호문을 `ARIA_decrypt`로 복호화한 결과를 RFC 기대 평문과 비교
- 두 테스트 모두 라운드별 중간값(키 XOR, S-box, diffusion)을 직접 계산하는 트레이스와 실제 함수 호출 결과를 각각 기대값과 비교합니다.

**결과**: Visual Studio와 gcc(MinGW) 두 환경 모두에서 `aria_test_encrypt`, `aria_test_decrypt` 실행 결과 아래와 같이 PASS로 확인되었습니다.

```
KAT(RFC 5794) trace : PASS
KAT(RFC 5794) func  : PASS
```

## 빌드 및 실행

### Visual Studio

1. 새 C 콘솔 프로젝트를 만듭니다.
2. `aria.h`, `aria_tables.c`, `aria_core.c`, `aria_cipher.c`를 프로젝트에 추가합니다.
3. `aria_test_encrypt.c` 또는 `aria_test_decrypt.c` 중 하나만 추가합니다. (두 파일 모두 `main` 함수를 포함하므로 동시에 추가하면 빌드 오류가 발생합니다.)
4. 빌드 후 실행하면 라운드별 중간값과 함께 `KAT(RFC 5794) trace : PASS`, `KAT(RFC 5794) func  : PASS` 결과가 출력됩니다.

### gcc(MinGW)
```
gcc aria_tables.c aria_core.c aria_cipher.c aria_test_encrypt.c -o aria_test_encrypt.exe
aria_test_encrypt.exe

gcc aria_tables.c aria_core.c aria_cipher.c aria_test_decrypt.c -o aria_test_decrypt.exe
aria_test_decrypt.exe
```
