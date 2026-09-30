/*
* aria_test_decrypt.c
* RFC 5794 Appendix A의 128/192/256비트 키 KAT 테스트 벡터로 ARIA_decrypt를 검증한다.
* aria_test_encrypt.c와 동일한 구조로, 라운드별 중간값을 dk를 사용해 직접 계산하는 트레이스와
* ARIA_decrypt 함수 호출 결과를 각각 구한 뒤, 두 결과와 RFC 기대 평문(expected)을 비교한다.
*/

#include "aria.h"
#include <stdio.h>
#include <string.h>

/* 16바이트 상태를 "label: 32자리 hex" 형식으로 한 줄 출력 */
static void print_state(const char* label, const uint8_t s[16])
{
	printf("%-22s", label);
	for (int i = 0; i < 16; i++)
		printf("%02x", s[i]);
	printf("\n");
}

int main(void)
{
	/*
	* RFC 5794 Appendix A 또는 KS X 1213-1 부속서 B 참고 
	* 128/192/256비트 테스트: key, ciphertext, expected를 표준 문서의 해당 벡터로 교체
	*/
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	uint8_t ciphertext[16] = { 0xf9, 0x2b, 0xd7, 0xc7, 0x9f, 0xb7, 0x2e, 0x2f, 0x2b, 0x8f, 0x80, 0xc1, 0x97, 0x2d, 0x24, 0xfc };
	uint8_t expected[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	ARIA_KEY ks;

	int keylen = sizeof(key);

	keyExpansion(key, keylen, &ks);
	if (ks.rounds == 0) {
		printf("키 길이가 올바르지 않습니다.\n");
		return 1;
	}

	int nr = ks.rounds - 1;

	uint8_t state[16], key_add[16], s_box[16], diff_lay[16];

	for (int j = 0; j < 16; j++)
		state[j] = ciphertext[j];

	print_state("round[0].input", ciphertext);

	/* 라운드별로 키 XOR → S-box → diffusion(마지막 라운드는 diffusion 생략, 최종 키 XOR) 과정을 재현 */
	for (int i = 1; i <= nr; i++) {
		char label[32];
		printf("\n");

		snprintf(label, sizeof(label), "round[%2d].start", i);
		print_state(label, state);

		for (int j = 0; j < 16; j++)
			key_add[j] = state[j] ^ ks.dk[i - 1][j];
		
		snprintf(label, sizeof(label), "round[%2d].key_add", i);
		print_state(label, key_add);

		/* 홀수 라운드는 SL1, 짝수 라운드는 SL2 적용 */
		if (i % 2 == 1)
			SL1(key_add, s_box);
		else
			SL2(key_add, s_box);
		
		snprintf(label, sizeof(label), "round[%2d].s_box", i);
		print_state(label, s_box);

		if (i < nr) {
			diffusion(s_box, diff_lay);
			
			snprintf(label, sizeof(label), "round[%2d].diff_lay", i);
			print_state(label, diff_lay);

			for (int j = 0; j < 16; j++)
				state[j] = diff_lay[j];
		}
		else {
			/* 마지막 라운드: diffusion 없이 S-box 결과를 최종 복호화 라운드 키(dk[nr])와 XOR */
			for (int j = 0; j < 16; j++)
				state[j] = s_box[j] ^ ks.dk[nr][j];
			
			snprintf(label, sizeof(label), "round[%2d].output", i);
			print_state(label, state);
		}
	}

	printf("\n");
	print_state("plaintext(trace): ", state);

	/* 실제 ARIA_decrypt 함수 호출 결과와 트레이스 결과, RFC 기대값을 모두 비교 */
	uint8_t plaintext[16];
	ARIA_decrypt(ciphertext, &ks, plaintext);
	print_state("plaintext(func): ", plaintext);

	printf("\n");

	int trace_pass = (memcmp(state, expected, 16) == 0);
	int kat_pass = (memcmp(plaintext, expected, 16) == 0);
	printf("KAT(RFC 5794) trace : %s\n", trace_pass ? "PASS" : "FAIL");
	printf("KAT(RFC 5794) func  : %s\n", kat_pass ? "PASS" : "FAIL");

	return (trace_pass && kat_pass) ? 0 : 1;
}