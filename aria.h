/*
* aria.h
* ARIA 블록 암호 구현의 공개 인터페이스.
* S-box, 확산 계층 상수, 라운드 함수, 키 스케줄, 암/복호화 함수를 선언한다.
* 참조: KS X 1213-1, RFC 5794
*/

#ifndef ARIA_H
#define ARIA_H

#include <stdint.h>

/* S-box: S1, S2는 원본 치환표, S3, S4는 각각 S1, S2의 역치환표 */
extern const uint8_t S1[256];
extern const uint8_t S2[256];
extern const uint8_t S3[256];
extern const uint8_t S4[256];

/* 확산 계층에 사용되는 16x16 involution 행렬. 2회 적용 시 원래 값으로 복원됨 */
extern const uint8_t A[16][16];

/* 키 스케줄 초기화용 라운드 상수. 키 길이(128/192/256)에 따라 CK1/CK2/CK3 적용 순서가 달라짐 */
extern const uint8_t CK[3][16];

/*
* 라운드 키 구조체
* ek: 암호화용 라운드 키, dk: 복호화용 라운드 키 (keyExpansion에서 채워짐)
* rounds: 저장된 라운드 키의 개수 (13/15/17 = 실제 라운드 수(12/14/16) + 1)
*/
typedef struct {
	uint8_t ek[17][16];
	uint8_t dk[17][16];
	int rounds;
} ARIA_KEY;

/* 치환 계층: 홀수 라운드는 S1→S2→S3→S4, 짝수 라운드는 S3→S4→S1→S2 순으로 적용 */
void SL1(const uint8_t* in, uint8_t* out);
void SL2(const uint8_t* in, uint8_t* out);

/* 확산 계층: 16바이트 입력 x에 KS X 1213-1 부속서 C.2 방법 Ⅱ(XOR 항 재사용)의 확산 변환을 적용해 y에 저장 */
void diffusion(const uint8_t x[16], uint8_t y[16]);

/* 홀수/짝수 라운드 함수: D^RK 계산 후 각각 SL1, SL2 적용, 이어서 diffusion 적용 */
void FO(const uint8_t D[16], const uint8_t RK[16], uint8_t out[16]);
void FE(const uint8_t D[16], const uint8_t RK[16], uint8_t out[16]);

/* 키 확장: 마스터 키(key, 키 길이 keylen=16/24/32)로부터 ek/dk와 rounds를 계산해 ks에 저장 */
void keyExpansion(const uint8_t* key, uint8_t keylen, ARIA_KEY* ks);

/* 128비트 오른쪽 순환 이동: in을 n비트만큼 우측 회전시켜 out에 저장 */
void ROT(const uint8_t in[16], int n, uint8_t out[16]);

/* 16바이트 블록 단위 암호화/복호화 */
void ARIA_encrypt(const uint8_t plaintext[16], const ARIA_KEY* ks, uint8_t ciphertext[16]);
void ARIA_decrypt(const uint8_t ciphertext[16], const ARIA_KEY* ks, uint8_t plaintext[16]);

#endif