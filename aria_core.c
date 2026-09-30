/*
* aria_core.c
* ARIA 라운드 함수(FO/FE), 확산 계층, 치환 계층, 키 확장(라운드 키 생성), 128비트 순환 이동 함수를 구현한다.
* 참조: KS X 1213-1, RFC 5794
*/

#include "aria.h"
#include <stddef.h>

/* 치환 계층(홀수 라운드): 4바이트 주기로 S1→S2→S3→S4 순서로 적용 */
void SL1(const uint8_t* in, uint8_t* out)
{
	for (int i = 0; i < 16; i++) {
		if (i % 4 == 0)
			out[i] = S1[in[i]];
		else if (i % 4 == 1)
			out[i] = S2[in[i]];
		else if (i % 4 == 2)
			out[i] = S3[in[i]];
		else
			out[i] = S4[in[i]];
	}
}

/* 치환 계층(짝수 라운드): S-box 적용 순서가 SL1과 반대(S3→S4→S1→S2) */
void SL2(const uint8_t* in, uint8_t* out)
{
	for (int i = 0; i < 16; i++) {
		if (i % 4 == 0)
			out[i] = S3[in[i]];
		else if (i % 4 == 1)
			out[i] = S4[in[i]];
		else if (i % 4 == 2)
			out[i] = S1[in[i]];
		else
			out[i] = S2[in[i]];
	}
}

/* [미사용 / 이전 구현] 확산 계층을 16x16 행렬 A와의 직접 곱셈(y=A·x)으로 계산한 버전
void diffusion(const uint8_t x[16], uint8_t y[16])
{
	for (int i = 0; i < 16; i++) {
		y[i] = 0;
		for (int j = 0; j < 16; j++)
			y[i] ^= A[i][j] * x[j];
	}
}
*/

/*
* 확산 계층: 16바이트 입력 x에 확산 변환(involution)을 적용해 y에 저장.
* KS X 1213-1 부속서 C.2 8비트 단위 구현 방법 Ⅱ 사용: 반복되는 XOR 항(T, U)을 미리 계산해 재사용
* (XOR 연산 수 96 → 52로 감소, 결과는 y=A·x와 동일)
*/
void diffusion(const uint8_t x[16], uint8_t y[16])
{
	uint8_t T[4], U[8];

	/* 4개 라인에서 공통으로 재사용되는 4개 항 */
	T[0] = x[3] ^ x[4] ^ x[9] ^ x[14];
	T[1] = x[2] ^ x[5] ^ x[8] ^ x[15];
	T[2] = x[1] ^ x[6] ^ x[11] ^ x[12];
	T[3] = x[0] ^ x[7] ^ x[10] ^ x[13];

	/* 추가로 재사용되는 8개 항 */
	U[0] = x[0] ^ x[5];
	U[1] = x[1] ^ x[10];
	U[2] = x[2] ^ x[7];
	U[3] = x[3] ^ x[13];
	U[4] = x[4] ^ x[15];
	U[5] = x[6] ^ x[8];
	U[6] = x[9] ^ x[12];
	U[7] = x[11] ^ x[14];

	/* 출력 128비트: T, U를 조합해 각 y[i] 계산 */
	y[0] = x[13] ^ U[5] ^ T[0];
	y[1] = x[7] ^ U[6] ^ T[1];
	y[2] = x[10] ^ U[4] ^ T[2];
	y[3] = x[5] ^ U[7] ^ T[3];
	y[4] = x[0] ^ U[7] ^ T[1];
	y[5] = x[15] ^ U[1] ^ T[0];
	y[6] = x[2] ^ U[6] ^ T[3];
	y[7] = x[8] ^ U[3] ^ T[2];
	y[8] = x[1] ^ U[4] ^ T[3];
	y[9] = x[14] ^ U[0] ^ T[2];
	y[10] = x[6] ^ U[3] ^ T[1];
	y[11] = x[12] ^ U[2] ^ T[0];
	y[12] = x[9] ^ U[2] ^ T[2];
	y[13] = x[3] ^ U[5] ^ T[3];
	y[14] = x[11] ^ U[0] ^ T[0];
	y[15] = x[4] ^ U[1] ^ T[1];
}

/* 홀수 라운드 함수: D(Data)^RK(Round Key) 계산 후 SL1, diffusion 순서로 적용 */
void FO(const uint8_t D[16], const uint8_t RK[16], uint8_t out[16])
{	
	uint8_t state[16];

	for (int i = 0; i < 16; i++) 
		state[i] = D[i] ^ RK[i];

	SL1(state, state);
	diffusion(state, out);
}

/* 짝수 라운드 함수: SL2 사용 외 FO와 구조 동일 */
void FE(const uint8_t D[16], const uint8_t RK[16], uint8_t out[16])
{
	uint8_t state[16];

	for (int i = 0; i < 16; i++)
		state[i] = D[i] ^ RK[i];

	SL2(state, state);
	diffusion(state, out);
}

/*
* 키 확장: keylen(16/24/32바이트)이 유효해야 하며, 아래 순서로 동작한다.
* 1) 키 확장 초기화: W0~W3 계산 (키 길이별 CK 시작 인덱스가 다름)
* 2) rounds(13/15/17)만큼 ek 생성, ROT 회전량은 4라운드 단위로 rkRotBits 순서를 따름
* 3) ek로부터 dk 생성 (양 끝은 ek를 그대로 뒤집어 사용, 중간은 diffusion 적용)
*/
void keyExpansion(const uint8_t* key, uint8_t keylen, ARIA_KEY* ks)
{
	uint8_t KR[16], W[4][16], ckstart, tmp[16];
	int i, j, nr;
	static const int rkRotBits[5] = { 19,31,67,97,109 }; /* 라운드 키 4개 그룹마다 적용하는 우측 순환 이동 비트 수 */

	if (key == NULL || ks == NULL) {
		if (ks != NULL)
			ks->rounds = 0;
		return;
	}

	if (keylen != 16 && keylen != 24 && keylen != 32) {
		ks->rounds = 0;		/* 0은 유효하지 않은 키 길이를 뜻함 */
		return;
	}

	/* 키 길이별로 CK1/CK2/CK3 역할에 매핑되는 CK 배열 시작 인덱스 */
	ckstart = (keylen == 16) ? 0 : (keylen == 24) ? 1 : 2;

	/* KL || KR = K || 0 ... 0, W0 = KL */
	for (i = 0; i < 16; i++) {
		W[0][i] = key[i];
		KR[i] = (i + 16 < keylen) ? key[i + 16] : 0;
	}

	/* W1 = FO(W0, CK1) ^ KR */
	FO(W[0], CK[ckstart], W[1]);
	for (i = 0; i < 16; i++)
		W[1][i] ^= KR[i];

	/* W2 = FE(W1, CK2) ^ W0 */
	FE(W[1], CK[(ckstart + 1) % 3], W[2]);
	for (i = 0; i < 16; i++)
		W[2][i] ^= W[0][i];

	/* W3 = FO(W2, CK3) ^ W1 */
	FO(W[2], CK[(ckstart + 2) % 3], W[3]);
	for (i = 0; i < 16; i++)
		W[3][i] ^= W[1][i];

	/* 라운드 키 개수: 13,15,17 = 실제 라운드(12/14/16) + 1 */
	nr = (keylen == 16) ? 12 : (keylen == 24) ? 14 : 16;
	ks->rounds = nr + 1;
	
	/* ek[i] = W[i%4] ^ ROT(W[(i+1)%4], rkRotBits[i/4]) 패턴을 4라운드 키 단위로 반복 */
	for (i = 0; i < ks->rounds; i++) {
		if (i % 4 == 0) {
			ROT(W[1], rkRotBits[i / 4], tmp);
			for (j = 0; j < 16; j++)
				ks->ek[i][j] = W[0][j] ^ tmp[j];
		}
		else if (i % 4 == 1) {
			ROT(W[2], rkRotBits[i / 4], tmp);
			for (j = 0; j < 16; j++)
				ks->ek[i][j] = W[1][j] ^ tmp[j];
		}
		else if (i % 4 == 2) {
			ROT(W[3], rkRotBits[i / 4], tmp);
			for (j = 0; j < 16; j++)
				ks->ek[i][j] = W[2][j] ^ tmp[j];
		}
		else {
			ROT(W[0], rkRotBits[i / 4], tmp);
			for (j = 0; j < 16; j++)
				ks->ek[i][j] = tmp[j] ^ W[3][j];
		}
	}

	/* dk 생성: dk[0]=ek[nr], dk[nr]=ek[0] (그대로 사용), 나머지는 diffusion(ek[nr-i]) */
	for (i = 0; i <= nr; i++) {
		if (i == 0)
			for (j = 0; j < 16; j++)
				ks->dk[i][j] = ks->ek[nr][j];
		else if (i == nr)
			for (j = 0; j < 16; j++)
				ks->dk[i][j] = ks->ek[0][j];
		else
			diffusion(ks->ek[nr - i], ks->dk[i]);
	}
}

/* 128비트 우측 순환 이동: n을 8로 나눈 몫(q, 바이트 단위 이동량)과 나머지(r, 바이트 경계를 넘는 비트 수)로 분해해 인접 바이트 조합으로 계산 */
void ROT(const uint8_t in[16], int n, uint8_t out[16])
{
	uint8_t a, b;
	int q, r;

	n = ((n % 128) + 128) % 128;
	q = n / 8;
	r = n % 8;

	for (int i = 0; i < 16; i++) {
		a = in[(i - q + 16) % 16];

		if (r == 0)
			out[i] = a;
		else {
			b = in[(i - q - 1 + 16) % 16];
			out[i] = ((a >> r) | (b << (8 - r))) & 0xFF;
		}
	}
}