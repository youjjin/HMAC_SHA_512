#include "HMAC_SHA_512.h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

void Change_digit(unsigned char* string, unsigned int* len, unsigned int* digit)
{
	char seps[] = "=, ,\t,\n";
	char *tok;

	int i, j;
	unsigned int result = 0, dig = 0;

	tok = strtok(string, seps);

	while (tok != NULL)
	{		

		if (strstr(tok, "Tlen") == NULL)
		{
			*len = strlen(tok);
			*digit = atoi(tok);
		}
		tok = strtok(NULL, seps);
	}
	
}

void Ascii(char* string, unsigned char* stream, int* len)
{

	char seps[] = "=, , \t, \n";
	char *tok;

	unsigned char buf[1025] = { 0, };
	int i = 0, j = 0, cnt = 0, n = 0;
	unsigned char result = 0, six = 0;
	int tmp = 0;
	tok = strtok(string, seps);


	while (tok != NULL)
	{
		if (strstr(tok, "K") == NULL && strstr(tok, "M") == NULL && strstr(tok, "T") == NULL && strstr(tok, "Tlen") == NULL && strstr(tok, "COUNT") == NULL)
		{
			*len = strlen(tok) / 2;

			while (j < strlen(tok))
			{
				result = 0;
				six = 0;

				for (i = j; i < j + 2; i++)
				{
					if (isalpha(tok[i]))
					{
						result = toupper(tok[i]) - 55;
						six = six * 16 + result;
					}
					else
					{
						result = tok[i] - 48;
						six = six * 16 + result;
					}
				}

				buf[n] = six;
				n++;
				j = j + 2;

				tmp = 1;

			}
		}
		tok = strtok(NULL, seps);
	}

	if (tmp == 1)
		memcpy(stream, buf, *len);
	else
	{
		stream = NULL;
		*len = 0;
	}
}

void HMAC_Test()
{
	FILE *fp_req;
	FILE *fp_fax;
	char L_buff[100];
	char Count_buff[100];
	char KLen_buff[1000];
	char TLen_buff[1000];
	char Key_buff[1200];
	char Msg_buff[1200];
	char buf[1000];//Enter

	int i;
	unsigned int* Len_len, Msg_len, KLen_len, TLen_len, Key_len;
	unsigned int* TLen = 0;
	unsigned int d_TLen = 0;
	unsigned char L[100] = { 0, };
	unsigned char Count[100] = { 0, };
	unsigned char KLen[1000] = { 0, };
	unsigned char Key[1200] = { 0, };
	unsigned char Msg[1200] = { 0, };
	unsigned char mac[1200] = { 0, };
	
	fp_req = fopen("HMAC-SHA512.req", "r");
	fp_fax = fopen("HMAC-SHA512.rsp", "w");

	if (fp_req == NULL || fp_fax == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	/****************L******************/
	fgets(L_buff, sizeof(L_buff), fp_req);
	printf("%s\n", L_buff);
	fputs(L_buff, fp_fax);
	fprintf(fp_fax, "\n");

	/****************Enter******************/
	fgets(buf, sizeof(buf), fp_req);
	memset(buf, 0, sizeof(buf));

	while (fgets(Count_buff, sizeof(Count_buff), fp_req) != NULL)
	{
		/****************Count******************/
		printf("%s", Count_buff);
		fputs(Count_buff, fp_fax);
		memset(Count_buff, 0, sizeof(Count_buff));
		
		/****************KLen******************/
		fgets(KLen_buff, sizeof(KLen_buff), fp_req);
		printf("%s", KLen_buff);
		fputs(KLen_buff, fp_fax);
		memset(KLen_buff, 0, sizeof(KLen_buff));

		/****************TLen******************/
		fgets(TLen_buff, sizeof(TLen_buff), fp_req);
		printf("%s", TLen_buff);
		fputs(TLen_buff, fp_fax);
		Change_digit(TLen_buff, &TLen_len, &TLen);
		memset(TLen_buff, 0, sizeof(TLen_buff));
		
		/****************Key******************/
		fgets(Key_buff, sizeof(Key_buff), fp_req);
		printf("%s", Key_buff);
		fputs(Key_buff, fp_fax);
		Ascii(Key_buff, Key, &Key_len);
		memset(Key_buff, 0, sizeof(Key_buff));

		/****************Msg******************/
		fgets(Msg_buff, sizeof(Msg_buff), fp_req);
		printf("%s", Msg_buff);
		fputs(Msg_buff, fp_fax);
		Ascii(Msg_buff, Msg, &Msg_len);

		if (Msg[0] == 00)
		{
			Msg[0] = NULL;
			Msg_len = 0;
		}

		memset(Msg_buff, 0, sizeof(Msg_buff));

		/*****************Enter***************/
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/****************HMAC***************/
		HMAC_SHA512_op(Msg, Msg_len, mac, Key, Key_len);

		/*****************MAC***************/
		printf("MAC = ");
		for (i = 0; i < TLen; i++)
		{
			printf("%02X", mac[i]);
		}
		printf("\n");
		printf("\n");

		fprintf(fp_fax, "MAC = ");
		for (i = 0; i < TLen; i++)
		{
			fprintf(fp_fax, "%02X", mac[i]);
		}
		fprintf(fp_fax, "\n");
		fprintf(fp_fax, "\n");
	}
	fclose(fp_req);
	fclose(fp_fax);
}