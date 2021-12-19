#include <WinSock2.h>
#include <iostream>
#include <cstring>
#include <mysql.h>
#include "openssl/applink.c"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <vector>
#include <time.h>
using namespace std;
#pragma warning (disable:4996)
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "libmysql.lib")

#define PORT	7777
#define COMPARE		65536
#define STR_SIZE	256

int _sha256(char* hashstr, char read_buf[]);
void db_select();
void Hash_g(char* num, BIGNUM* result);
void TwoProver(BIGNUM* g1, BIGNUM* x_0, BIGNUM* x_1, BIGNUM* y, char* pi[]);
bool EqualVerifier(BIGNUM* S, char* pi_0, char* pi_1, char* pi_2);
void socket_receive(SOCKET socket, char* Buffer, int str_size = 256);
void memory_assign(char*** dest, int size);
void memory_free(char*** dest, int size);

char** X;
char** ALPHA;
char** DELTA;
char** R_i;
char** BETA;
char** U;
int X_size, Y_size;

BIGNUM* q = BN_new();
BIGNUM* p = BN_new();
BIGNUM* one = BN_new();
BIGNUM* g_0 = BN_new();
BIGNUM* g_1 = BN_new();
BIGNUM* g_2 = BN_new();
BN_CTX* ctx = BN_CTX_new();
BIGNUM* temp = BN_new();

char zero[] = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
// client program
int main(int argc, char* argv[]) {

	if (argc < 2) {
		cout << "서버의 ip주소의 입력이 필요합니다." << endl;
		return 0;
	}

	cout << argv[1] << endl;

	db_select();

	memory_assign(&ALPHA, X_size);
	memory_assign(&DELTA, X_size);
	memory_assign(&R_i, X_size);

	BN_set_word(one, 1);

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET hSocket;
	hSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	SOCKADDR_IN tAddr = {};
	tAddr.sin_family = AF_INET;
	tAddr.sin_port = htons(PORT);
	tAddr.sin_addr.s_addr = inet_addr(argv[1]);

	connect(hSocket, (SOCKADDR*)&tAddr, sizeof(tAddr));

	char cBuffer[STR_SIZE + 1] = { 0 };
	recv(hSocket, cBuffer, STR_SIZE, 0);

	send(hSocket, "ok", (int)strlen("ok"), 0);

	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	socket_receive(hSocket, cBuffer);
	BN_hex2bn(&q, cBuffer);

	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	socket_receive(hSocket, cBuffer);
	BN_hex2bn(&g_0, cBuffer);

	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	socket_receive(hSocket, cBuffer);
	BN_hex2bn(&g_1, cBuffer);

	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	socket_receive(hSocket, cBuffer);
	BN_hex2bn(&g_2, cBuffer);

	BN_lshift1(p, q);
	BN_add(p, p, one);  // p = q*2+1
	// end setup

	clock_t start, end;
	double result = 0;

	start = clock();  // time start

	BIGNUM* A = BN_new();
	BN_set_word(A, 1);
	for (int i = 0; i < X_size; i++) {
		Hash_g(X[i], temp);
		BN_mod_mul(A, temp, A, p, ctx);
	}

	BIGNUM* R = BN_new();
	BIGNUM* B = BN_new();

	BN_rand_range(R, q);
	while (BN_is_zero(R)) BN_rand_range(R, q);

	BN_mod_exp(temp, g_0, R, p, ctx);
	BN_mod_mul(B, A, temp, p, ctx);

	BIGNUM* inverse = BN_new();
	BIGNUM* B_i = BN_new();
	BIGNUM* X_hash = BN_new();
	BIGNUM* r_i = BN_new();

	for (int i = 0; i < X_size; i++) {
		Hash_g(X[i], X_hash);
		BN_mod_inverse(inverse, X_hash, p, ctx);
		BN_mod_mul(B_i, A, inverse, p, ctx);
		BN_rand_range(r_i, q);
		while (BN_is_zero(r_i)) BN_rand_range(r_i, q);
		strcpy(R_i[i], BN_bn2hex(r_i));

		BN_mod_exp(temp, g_1, r_i, p, ctx);
		BN_mod_mul(temp, temp, X_hash, p, ctx);
		strcpy(ALPHA[i], BN_bn2hex(temp));

		BN_mod_exp(temp, g_2, r_i, p, ctx);
		BN_mod_mul(temp, temp, B_i, p, ctx);
		strcpy(DELTA[i], BN_bn2hex(temp));
	}

	BN_free(inverse);
	BN_free(B_i);
	BN_free(r_i);
	BN_free(X_hash);

	//----------------TwoProver----------------------------
	char* pi_c[3];

	BIGNUM* h = BN_new();
	BIGNUM* TwoProver_R_1 = BN_new();
	BIGNUM* y = BN_new();
	BIGNUM* alpha_inverse = BN_new();
	BIGNUM* delta_inverse = BN_new();

	// y 
	BN_hex2bn(&alpha_inverse, ALPHA[0]);
	BN_hex2bn(&delta_inverse, DELTA[0]);
	BN_mod_inverse(alpha_inverse, alpha_inverse, p, ctx);
	BN_mod_inverse(delta_inverse, delta_inverse, p, ctx);

	BN_mod_mul(y, alpha_inverse, delta_inverse, p, ctx);
	BN_mod_mul(y, y, B, p, ctx);

	// h 
	BN_mod_mul(h, g_1, g_2, p, ctx);

	// R_1
	BN_hex2bn(&TwoProver_R_1, R_i[0]);

	// TwoProver(BIGNUM *g1, BIGNUM *x_0, BIGNUM *x_1, BIGNUM *y, char* pi[])
	TwoProver(h, R, TwoProver_R_1, y, pi_c);

	BN_free(h);
	BN_free(y);
	BN_free(alpha_inverse);
	BN_free(delta_inverse);
	BN_free(TwoProver_R_1);

	end = clock(); //시간 측정 끝
	result += (double)(end - start);

	// send server <B, (ALPHA[0], ALPHA[1], ... , ALPHA[n]), (DELTA[0], DELTA[1], ... , DELTA[n), pi_c>
	char buff[100] = { 0 };
	sprintf(buff, "%d", X_size);
	send(hSocket, buff, (int)strlen(buff), 0);
	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	recv(hSocket, cBuffer, STR_SIZE, 0);
	if (strcmp(cBuffer, "ok") == 0) {
		int len;
		// send B
		char* text = BN_bn2hex(B);
		len = (int)strlen(text);
		send(hSocket, zero, STR_SIZE - len, 0);
		send(hSocket, text, len, 0);
		// send ALPHA 
		for (int i = 0; i < X_size; i++) {
			len = (int)strlen(ALPHA[i]);
			send(hSocket, zero, STR_SIZE - len, 0);
			send(hSocket, ALPHA[i], len, 0);
		}
		// send DELTA 
		for (int i = 0; i < X_size; i++) {
			len = (int)strlen(DELTA[i]);
			send(hSocket, zero, STR_SIZE - len, 0);
			send(hSocket, DELTA[i], len, 0);
		}
		// send pi_c 
		for (int i = 0; i < 3; i++) {
			len = (int)strlen(pi_c[i]);
			send(hSocket, zero, STR_SIZE - len, 0);
			send(hSocket, pi_c[i], len, 0);
		}
	}
	memory_free(&DELTA, X_size);
	// Receive <S, (BETA[0], .., BETA[n]), (U[0], .., U[m]), pi_s>

	char pi_s[3][STR_SIZE + 1] = { 0 };
	BIGNUM* S = BN_new();

	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	recv(hSocket, cBuffer, STR_SIZE, 0);

	Y_size = atoi(cBuffer);
	send(hSocket, "ok", (int)strlen("ok"), 0);

	memory_assign(&BETA, X_size);
	memory_assign(&U, Y_size);

	// receive S
	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	socket_receive(hSocket, cBuffer);
	BN_hex2bn(&S, cBuffer);
	// receive BETA
	for (int i = 0; i < X_size; i++) {
		socket_receive(hSocket, BETA[i]);
	}
	// receive U
	char str[5] = { 0 };
	vector<int>* link = new vector<int>[COMPARE];
	for (int i = 0; i < Y_size; i++) {
		socket_receive(hSocket, U[i], 64);
		for (int k = 0; k < 4; k++) str[k] = U[i][k];
		link[(int)strtol(str, NULL, 16)].push_back(i);
	}
	// receive pi_s
	for (int i = 0; i < 3; i++) {
		memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
		socket_receive(hSocket, cBuffer);
		strcpy(pi_s[i], cBuffer);
	}
	closesocket(hSocket);
	WSACleanup();              // socket end

	start = clock();    // time start

	if (EqualVerifier(S, pi_s[0], pi_s[1], pi_s[2])) {
		cout << "\nEqualVerifier successful\n";

		memory_free(&ALPHA, X_size);

		BIGNUM* S_inverse = BN_new();
		BIGNUM* K_i = BN_new();
		BIGNUM* beta = BN_new();

		BN_mod_inverse(S_inverse, S, p, ctx);
		int index, num = 0;

		end = clock();      // time end
		result += (double)(end - start);

		for (int i = 0; i < X_size; i++) {
			char tt[800] = { 0 }, C[65] = { 0 };

			start = clock();    // time start

			BN_hex2bn(&beta, BETA[i]);
			BN_hex2bn(&temp, R_i[i]);
			BN_mod_exp(K_i, S_inverse, temp, p, ctx);
			BN_mod_mul(K_i, beta, K_i, p, ctx);

			strcat(tt, BN_bn2hex(K_i));
			BIGNUM* hash = BN_new();
			Hash_g(X[i], hash);
			strcat(tt, BN_bn2hex(hash));
			strcat(tt, X[i]);
			BN_free(hash);
			_sha256(C, tt);

			end = clock();      // time end
			result += (double)(end - start);

			for (int j = 0; j < 4; j++) str[j] = C[j];
			index = (int)strtol(str, NULL, 16);

			for (int k = 0; k < link[index].size(); k++) {
				if (strcmp(U[link[index][k]], C) == 0) {
					cout << i << "  :  " << X[i] << endl;
					num++;
					break;
				}
			}
		}
		cout << "교집합 연산 결과 개수 : " << num << endl;
		cout << "계산 시간 : " << result / 1000 << " 초" << endl;

		BN_free(beta);
		BN_free(K_i);
		BN_free(S_inverse);

		memory_free(&U, Y_size);

	}
	else {
		cout << "EqualVerifier fail" << endl;
		memory_free(&ALPHA, X_size);
	}

	BN_free(g_0);
	BN_free(g_1);
	BN_free(g_2);
	BN_free(S);
	BN_free(p);
	BN_free(R);
	BN_free(B);
	BN_free(A);
	BN_free(one);
	BN_free(q);
	BN_CTX_free(ctx);
	BN_free(temp);

	memory_free(&X, X_size);
	memory_free(&R_i, X_size);
	memory_free(&BETA, X_size);

	return 0;
}
int _sha256(char* hashstr, char read_buf[]) {
	unsigned char hash[SHA256_DIGEST_LENGTH];

	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	int readlen = (int)strlen(read_buf);

	SHA256_Update(&sha256, read_buf, readlen);
	SHA256_Final(hash, &sha256);

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(hashstr + (i * 2), "%02x", hash[i]);
	}
	hashstr[64] = 0;
	return 0;
}
void memory_assign(char*** dest, int size) {
	*dest = new char* [size];
	for (int i = 0; i < size; i++) {
		(*dest)[i] = new char[STR_SIZE + 1];
		memset((*dest)[i], 0, sizeof(char) * (STR_SIZE + 1));
	}
}
void memory_free(char*** dest, int size) {
	for (int i = 0; i < size; i++) {
		delete[](*dest)[i];
	}
	delete[](*dest);
}
void socket_receive(SOCKET socket, char* Buffer, int str_size) {
	recv(socket, Buffer, str_size, 0);
	int get = (int)strlen(Buffer);
	while (get < str_size) {
		char recv_temp[STR_SIZE + 1] = { 0 };
		recv(socket, recv_temp, str_size - get, 0);
		get += (int)strlen(recv_temp);
		strcat(Buffer, recv_temp);
	}

}
void TwoProver(BIGNUM* g1, BIGNUM* x_0, BIGNUM* x_1, BIGNUM* y, char* pi[]) {
	BIGNUM* R_prover_1 = BN_new();
	BIGNUM* R_prover_0 = BN_new();
	BIGNUM* temp2 = BN_new();
	BIGNUM* beta = BN_new();
	BIGNUM* z_0 = BN_new();
	BIGNUM* z_1 = BN_new();
	BIGNUM* E = BN_new();

	char e[800] = { 0 }, hash_result[65] = { 0 };

	BN_rand_range(R_prover_0, q);
	while (BN_is_zero(R_prover_0)) BN_rand_range(R_prover_0, q);
	BN_rand_range(R_prover_1, q);
	while (BN_is_zero(R_prover_1)) BN_rand_range(R_prover_1, q);

	//beta 
	BN_mod_exp(temp, g_0, R_prover_0, p, ctx);
	BN_mod_exp(temp2, g1, R_prover_1, p, ctx);
	BN_mod_mul(beta, temp, temp2, p, ctx);

	//e
	strcat(e, BN_bn2hex(p));
	strcat(e, BN_bn2hex(y));
	strcat(e, BN_bn2hex(beta));

	_sha256(hash_result, e);
	BN_hex2bn(&E, hash_result);

	// z_0 
	BN_mod_mul(z_0, E, x_0, q, ctx);
	BN_mod_sub(z_0, R_prover_0, z_0, q, ctx);

	// z_1 
	BN_mod_mul(z_1, E, x_1, q, ctx);
	BN_mod_add(z_1, z_1, R_prover_1, q, ctx);

	pi[0] = BN_bn2hex(beta);
	pi[1] = BN_bn2hex(z_0);
	pi[2] = BN_bn2hex(z_1);

	BN_free(R_prover_1);
	BN_free(R_prover_0);
	BN_free(beta);
	BN_free(temp2);
	BN_free(E);
	BN_free(z_1);
	BN_free(z_0);
}
bool EqualVerifier(BIGNUM* S, char* pi_0, char* pi_1, char* pi_2) {
	bool result = FALSE;
	BIGNUM* server_E = BN_new();
	BIGNUM* v_0 = BN_new();
	BIGNUM* v_1 = BN_new();
	BIGNUM* PI_0 = BN_new();
	BIGNUM* PI_1 = BN_new();
	BIGNUM* PI_2 = BN_new();

	char Server_e[1500] = { 0 };
	char hash_result[65] = { 0 };

	BN_hex2bn(&PI_0, pi_0);
	BN_hex2bn(&PI_1, pi_1);
	BN_hex2bn(&PI_2, pi_2);

	strcat(Server_e, BN_bn2hex(p));
	strcat(Server_e, BN_bn2hex(S));
	BN_hex2bn(&temp, BETA[0]);
	strcat(Server_e, BN_bn2hex(temp));
	strcat(Server_e, BN_bn2hex(PI_0));
	strcat(Server_e, BN_bn2hex(PI_1));

	_sha256(hash_result, Server_e);
	BN_hex2bn(&server_E, hash_result);

	// v_0 
	BN_mod_exp(v_0, g_1, PI_2, p, ctx);
	BN_mod_exp(temp, S, server_E, p, ctx);
	BN_mod_mul(v_0, v_0, temp, p, ctx);

	// v_1 
	BN_hex2bn(&temp, ALPHA[0]);
	BN_mod_exp(v_1, temp, PI_2, p, ctx);
	BN_hex2bn(&temp, BETA[0]);
	BN_mod_exp(temp, temp, server_E, p, ctx);
	BN_mod_mul(v_1, v_1, temp, p, ctx);

	if (BN_cmp(PI_0, v_0) == 0 && BN_cmp(PI_1, v_1) == 0) {
		result = TRUE;
	}
	BN_free(server_E);
	BN_free(PI_0);
	BN_free(PI_1);
	BN_free(PI_2);
	BN_free(v_0);
	BN_free(v_1);
	return result;
}
void Hash_g(char* num, BIGNUM* result) {
	BIGNUM* exp = BN_new();
	BN_hex2bn(&exp, num);
	// r = a ^ p mod m - > temp = g_0 ^ exp mod p 
	BN_mod_exp(result, g_0, exp, p, ctx);

	BN_free(exp);
}

void db_select() {

	MYSQL* conn;
	MYSQL_ROW row;
	MYSQL_RES* res = NULL;
	int qstate, q_count;
	conn = mysql_init(0);
	conn = mysql_real_connect(conn, "localhost", "root", "root", "test", 3306, NULL, 0);

	if (conn) {
		puts("Successful connection to database!");

		string query_count = "SELECT count(*) FROM privatesetx";
		string query = "SELECT Value FROM privatesetx";

		const char* count = query_count.c_str();
		const char* q = query.c_str();

		q_count = mysql_query(conn, count);
		if (!q_count) {
			MYSQL_RES* ans = mysql_store_result(conn);
			row = mysql_fetch_row(ans);
			X_size = atoi(*row);
			cout << X_size << endl;
			mysql_free_result(ans);
		}
		memory_assign(&X, X_size);

		qstate = mysql_query(conn, q);
		if (!qstate) {
			cout << "query successful" << endl;
			int i = 0;
			res = mysql_store_result(conn);
			while (row = mysql_fetch_row(res)) {
				strcpy(X[i++], row[0]);
			}
		}
		else {
			cout << "Query failed: " << mysql_error(conn) << endl;
		}
	}
	else {
		cout << "Connection to database has falied!" << endl;
	}

	mysql_free_result(res);
	mysql_close(conn);
}