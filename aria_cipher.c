/*
* aria_cipher.c
* ARIA 블록 암호화/복호화 본체. keyExpansion으로 미리 채워진 ks->ek, ks->dk를 읽기만 함.
* 라운드 함수(FO/FE)를 번갈아 적용한 뒤 마지막 라운드에서 SL2와 XOR로 마무리한다.
*/

#include "aria.h"

/* 암호화: 1~(nr-1) 라운드는 FO/FE 번갈아 적용, 마지막 라운드는 SL2와 XOR로 마무리 */
void ARIA_encrypt(const uint8_t plaintext[16], const ARIA_KEY* ks, uint8_t ciphertext[16])
{
	uint8_t state[16];
	int i, nr;

	nr = ks->rounds - 1;

	for (i = 0; i < 16; i++)
		state[i] = plaintext[i];
		
	/* 홀수 라운드는 FO(ek[0], ek[2], ...), 짝수 라운드는 FE(ek[1], ek[3], ...) 적용 */
	for (i = 1; i < nr; i++){
		if (i % 2 == 1)
			FO(state, ks->ek[i - 1], state);
		else
			FE(state, ks->ek[i - 1], state);
	}

	/* 마지막 라운드: ek[nr-1]과 XOR 후 diffusion 없이 SL2만 적용 */
	for (i = 0; i < 16; i++)
		state[i] ^= ks->ek[nr - 1][i];

	SL2(state, state);

	/* 최종 출력: ek[nr]과 XOR */
	for (i = 0; i < 16; i++)
		ciphertext[i] = state[i] ^ ks->ek[nr][i];
}

/* 복호화: ek 대신 ks->dk를 사용하는 것 외에는 ARIA_encrypt와 구조 동일 */
void ARIA_decrypt(const uint8_t ciphertext[16], const ARIA_KEY* ks, uint8_t plaintext[16])
{
	uint8_t state[16];
	int i, nr;

	nr = ks->rounds - 1;

	for (i = 0; i < 16; i++)
		state[i] = ciphertext[i];

	for (i = 1; i < nr; i++) {
		if (i % 2 == 1)
			FO(state, ks->dk[i - 1], state);
		else
			FE(state, ks->dk[i - 1], state);
	}

	for (i = 0; i < 16; i++)
		state[i] ^= ks->dk[nr - 1][i];

	SL2(state, state);

	for (i = 0; i < 16; i++)
		plaintext[i] = state[i] ^ ks->dk[nr][i];
}