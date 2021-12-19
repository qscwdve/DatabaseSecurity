#include <WinSock2.h>
#include <mysql.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <cstring>
#include <iostream>
#include <time.h>
#pragma warning (disable:4996)
#pragma comment(lib, "libmysql.lib")
#pragma comment(lib, "ws2_32")
using namespace std;

#define PORT	7777
#define STR_SIZE	256

void socket_receive(SOCKET socket, char* Buffer);
void Hash_g(char* num, BIGNUM* result);
void db_select();
int _sha256(char* hashstr, char read_buf[]);
void make_str(char* dest, char* source);
bool TwoVerifier(BIGNUM* B, char* pi_0, char* pi_1, char* pi_2);
void EqualProver(BIGNUM* S, BIGNUM* R, char* pi, char* pi2, char* pi3);
void memory_assign(char*** dest, int size);
void memory_free(char*** dest, int size);
void prime(BIGNUM* p, BIGNUM* q);
void prime_generator();

char** Y;
char** ALPHA;  //X_size
char** DELTA;  //X_size
char** BETA;
char** U;
int Y_size, X_size;

BIGNUM* q = BN_new();
BIGNUM* p = BN_new();
BIGNUM* one = BN_new();
BIGNUM* g_0 = BN_new();
BIGNUM* g_1 = BN_new();
BIGNUM* g_2 = BN_new();
BN_CTX* ctx = BN_CTX_new();
BIGNUM* temp = BN_new();

char zero[STR_SIZE + 1] = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

// Server program
int main() {

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET hListen;
	hListen = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	SOCKADDR_IN tListenAddr;
	tListenAddr.sin_family = AF_INET;
	tListenAddr.sin_port = htons(PORT);
	tListenAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	bind(hListen, (SOCKADDR*)&tListenAddr, sizeof(tListenAddr));
	listen(hListen, SOMAXCONN);

	SOCKADDR_IN tClntAddr;
	int iClntSize = sizeof(tClntAddr);
	SOCKET hClient = accept(hListen, (SOCKADDR*)&tClntAddr, &iClntSize);

	cout << "소켓 통신 연결 완료" << endl;

	clock_t start, end;
	double result = 0;

	BN_set_word(one, 1);
	prime(p, q);
	prime_generator();
	cout << "prime P : " << BN_bn2dec(p) << "\n\n";
	char send_msg[1500] = { 0 };
	
	make_str(send_msg, BN_bn2hex(q));
	make_str(send_msg, BN_bn2hex(g_0));
	make_str(send_msg, BN_bn2hex(g_1));
	make_str(send_msg, BN_bn2hex(g_2));

	send(hClient, "4", 1, 0);

	char cBuffer[STR_SIZE + 1] = { 0 };
	recv(hClient, cBuffer, STR_SIZE, 0);

	if (strcmp(cBuffer, "ok") == 0) {
		send(hClient, send_msg, (int)strlen(send_msg), 0);
	}

	// end setup

	db_select();

	start = clock();  // time start

	BIGNUM* R = BN_new();
	BN_rand_range(R, q);
	while (BN_is_zero(R)) BN_rand_range(R, q);

	// U
	memory_assign(&U, Y_size);
	BIGNUM* S_i = BN_new();
	BIGNUM* K_i = BN_new();
	for (int i = 0; i < Y_size; i++) {
		Hash_g(Y[i], S_i);
		BN_mod_exp(K_i, S_i, R, p, ctx);
		char tt[800] = { 0 };
		strcat(tt, BN_bn2hex(K_i));
		strcat(tt, BN_bn2hex(S_i));
		strcat(tt, Y[i]);
		_sha256(U[i], tt);
	}
	BN_free(S_i);
	BN_free(K_i);
	memory_free(&Y, Y_size);

	end = clock(); // time end
	result += (double)(end - start);

	// Receive server <B, (ALPHA[0], ALPHA[1], ... , ALPHA[n]), (DELTA[0], DELTA[1], ... , DELTA[n), pi_c>
	BIGNUM* B = BN_new();
	char pi_c[3][STR_SIZE + 1] = { 0 };
	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	recv(hClient, cBuffer, STR_SIZE, 0);

	X_size = atoi(cBuffer);

	memory_assign(&ALPHA, X_size);
	memory_assign(&DELTA, X_size);

	send(hClient, "ok", 2, 0);

	memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
	socket_receive(hClient, cBuffer);
	BN_hex2bn(&B, cBuffer);      // receive B
	for (int i = 0; i < X_size; i++) {
		socket_receive(hClient, ALPHA[i]);         // receive ALPHA 
	}
	for (int i = 0; i < X_size; i++) {
		socket_receive(hClient, DELTA[i]);         // receive DELTA 
	}
	for (int i = 0; i < 3; i++) {
		memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
		socket_receive(hClient, cBuffer);
		strcpy(pi_c[i], cBuffer);          // receive pi_c 
	}

	start = clock();  // time start

	// TwoVerifier
	if (TwoVerifier(B, pi_c[0], pi_c[1], pi_c[2])) {
		cout << "TwoVerifier successful" << endl;

		memory_free(&DELTA, X_size);

		// EqualProver

		BIGNUM* S = BN_new();
		BIGNUM* alpha = BN_new();
		
		memory_assign(&BETA, X_size);

		BN_mod_exp(S, g_1, R, p, ctx);
		for (int i = 0; i < X_size; i++) {
			BN_hex2bn(&alpha, ALPHA[i]);
			BN_mod_exp(temp, alpha, R, p, ctx);
			strcpy(BETA[i], BN_bn2hex(temp));
		}

		char pi_s[3][STR_SIZE + 1] = { 0 };
		EqualProver(S, R, pi_s[0], pi_s[1], pi_s[2]);

		memory_free(&ALPHA, X_size);
		
		end = clock();  // time end
		result += (double)(end - start);

		//  send  client < S, (BETA[0], ..., BETA[n]), (U[0], ..., U[m]), pi_s >
		char buff[100] = { 0 };
		sprintf(buff, "%d", Y_size);
		send(hClient, buff, (int)strlen(buff), 0);
		memset(cBuffer, 0, (STR_SIZE + 1) * sizeof(char));
		recv(hClient, cBuffer, STR_SIZE, 0);
		if (strcmp(cBuffer, "ok") == 0) {
			int len;
			// send S
			char *text = BN_bn2hex(S);
			len = (int)strlen(text);
			send(hClient, zero, STR_SIZE - len, 0);
			send(hClient, text, len, 0);
			// send BETA 
			for (int i = 0; i < X_size; i++) {
				len = (int)strlen(BETA[i]);
				send(hClient, zero, STR_SIZE - len, 0);
				send(hClient, BETA[i], len, 0);
			}
			// send U -> Hash 
			for (int i = 0; i < Y_size; i++) {
				send(hClient, U[i], 64, 0);
			}
			// send pi_s 
			for (int i = 0; i < 3; i++) {
				len = (int)strlen(pi_s[i]);
				send(hClient, zero, STR_SIZE - len, 0);
				send(hClient, pi_s[i], len, 0);
			}
		}
		BN_free(R);
		BN_free(S);
		BN_free(alpha);
		memory_free(&BETA, X_size);
		memory_free(&U, Y_size);
	}
	else {
		cout << "TwoVerifier fail" << endl;
		memory_free(&DELTA, X_size);
		memory_free(&ALPHA, X_size);
	}

	closesocket(hClient);
	closesocket(hListen);

	WSACleanup();

	cout << "server end" << endl;
	cout << "계산 시간 : " << result / 1000  << " 초" << endl;

	BN_free(g_0);
	BN_free(g_1);
	BN_free(g_2);
	BN_free(p);
	BN_free(B);
	BN_free(one);
	BN_free(q);
	BN_CTX_free(ctx);
	BN_free(temp);

	return 0;
}
void socket_receive(SOCKET socket, char* Buffer) {
	recv(socket, Buffer, STR_SIZE, 0);
	int get = (int)strlen(Buffer);
	while (get < STR_SIZE) {
		char recv_temp[STR_SIZE + 1] = { 0 };
		recv(socket, recv_temp, STR_SIZE - get, 0);
		get += (int)strlen(recv_temp);
		strcat(Buffer, recv_temp);
	}
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
void make_str(char *dest, char *source) {
	char* q = dest, *s = source;
	int len = STR_SIZE - strlen(source);
	while (*q != NULL) q++;
	while (len > 0) {
		*q++ = '0';
		len--;
	}
	while (*s != NULL) {
		*q++ = *s++;
	}
}
void prime(BIGNUM* p, BIGNUM* q) {

	if (RAND_status()) cout << "Rand seed success" << endl;
	else {
		while (RAND_status() == 0) {
			static const char rnd_seed[] = "string to make the random number generator think it has entropy";
			RAND_seed(rnd_seed, sizeof rnd_seed);
		}
	}
	cout << "prime generate start" << endl;
	BN_generate_prime_ex(p, 1024, 1, NULL, NULL, NULL);
	BN_rshift1(q, p);
}
void prime_generator() {
	BIGNUM* two = BN_new();
	BIGNUM* result = BN_new();

	BN_add(two, one, one);

	while (1) {
		BN_rand_range(g_0, p);
		while (BN_is_zero(g_0) || BN_is_one(g_0)) BN_rand_range(g_0, p);
		BN_mod_exp(result, g_0, two, p, ctx);
		if (!BN_is_one(result)) {
			BN_sub(result, p, one);
			BN_mod_exp(result, g_0, result, p, ctx);
			if (BN_is_one(result)) {
				BN_mod_exp(result, g_0, q, p, ctx);
				if (BN_is_one(result)) break;
			}
		}
	}
	BN_mod_exp(g_1, g_0, two, p, ctx);
	BN_add(result, two, two);
	BN_mod_exp(g_2, g_0, result, p, ctx);

	BN_free(two);
	BN_free(result);
}
void db_select() {

	MYSQL* conn;
	MYSQL_ROW row;
	MYSQL_RES* res = NULL;
	int qstate, q_count;

	conn = mysql_init(0);
	conn = mysql_real_connect(conn, "localhost", "root", "root", "test", 3306, NULL, 0);

	if (conn) {
		cout << "Successful connection to database!" << endl;

		string query_count = "SELECT count(*) FROM privatesety";
		string query = "SELECT Value FROM privatesety";

		const char* count = query_count.c_str();
		const char* q = query.c_str();

		q_count = mysql_query(conn, count);
		if (!q_count) {
			MYSQL_RES* ans = mysql_store_result(conn);
			row = mysql_fetch_row(ans);
			Y_size = atoi(*row);
			cout << Y_size << endl;
		}
		memory_assign(&Y, Y_size);

		qstate = mysql_query(conn, q);
		if (!qstate) {
			cout << "query successful" << endl;
			int i = 0;
			res = mysql_store_result(conn);
			while (row = mysql_fetch_row(res)) {
				strcpy(Y[i++], row[0]);
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
bool TwoVerifier(BIGNUM* B, char* pi_0, char* pi_1, char* pi_2) {
	BIGNUM* alpha_inverse = BN_new();
	BIGNUM* delta_inverse = BN_new();
	BIGNUM* y = BN_new();
	BIGNUM* h = BN_new();
	BIGNUM* v = BN_new();
	BIGNUM* pi_c_1 = BN_new();
	BIGNUM* pi_c_2 = BN_new();
	BIGNUM* pi_c_0 = BN_new();
	BIGNUM* E = BN_new();

	char hash_result[65] = { 0 };
	char e[1000] = { 0 };
	bool result = FALSE;

	BN_hex2bn(&pi_c_0, pi_0);
	BN_hex2bn(&alpha_inverse, ALPHA[0]);
	BN_hex2bn(&delta_inverse, DELTA[0]);
	BN_mod_inverse(alpha_inverse, alpha_inverse, p, ctx);
	BN_mod_inverse(delta_inverse, delta_inverse, p, ctx);

	BN_mod_mul(y, alpha_inverse, delta_inverse, p, ctx);
	BN_mod_mul(y, y, B, p, ctx);

	BN_mod_mul(h, g_1, g_2, p, ctx);

	strcat(e, BN_bn2hex(p));
	strcat(e, BN_bn2hex(y));
	strcat(e, BN_bn2hex(pi_c_0));

	_sha256(hash_result, e);

	BN_hex2bn(&pi_c_1, pi_1);
	BN_hex2bn(&pi_c_2, pi_2);
	BN_hex2bn(&E, hash_result);
	BN_mod_exp(v, g_0, pi_c_1, p, ctx);
	BN_mod_exp(temp, h, pi_c_2, p, ctx);
	BN_mod_mul(v, v, temp, p, ctx);
	BN_mod_exp(temp, y, E, p, ctx);
	BN_mod_mul(v, v, temp, p, ctx);

	if (BN_cmp(v, pi_c_0) == 0) result = TRUE;

	BN_free(h);
	BN_free(E);
	BN_free(v);
	BN_free(pi_c_1);
	BN_free(pi_c_0);
	BN_free(pi_c_2);
	BN_free(alpha_inverse);
	BN_free(y);
	BN_free(delta_inverse);

	return result;
}
void EqualProver(BIGNUM* S, BIGNUM* R, char* pi, char* pi2, char* pi3) {
	BIGNUM* r = BN_new();
	BIGNUM* beta_0 = BN_new();
	BIGNUM* beta_1 = BN_new();
	BIGNUM* BETA_0 = BN_new();    // BETA[0] 
	BIGNUM* alp = BN_new();
	BIGNUM* Z = BN_new();
	BIGNUM* server_E = BN_new();
	
	char hash_result[65] = { 0 };
	char Server_e[1500] = { 0 };

	BN_hex2bn(&alp, ALPHA[0]);
	BN_hex2bn(&BETA_0, BETA[0]);

	BN_rand_range(r, q);
	while (BN_is_zero(r)) BN_rand_range(r, q);

	BN_mod_exp(beta_0, g_1, r, p, ctx);
	BN_mod_exp(beta_1, alp, r, p, ctx);

	strcat(Server_e, BN_bn2hex(p));
	strcat(Server_e, BN_bn2hex(S));
	strcat(Server_e, BN_bn2hex(BETA_0));
	strcat(Server_e, BN_bn2hex(beta_0));
	strcat(Server_e, BN_bn2hex(beta_1));

	_sha256(hash_result, Server_e);
	BN_hex2bn(&server_E, hash_result);

	BN_mod_mul(Z, server_E, R, q, ctx);
	BN_mod_sub(Z, r, Z, q, ctx);

	strcpy(pi, BN_bn2hex(beta_0));
	strcpy(pi2, BN_bn2hex(beta_1));
	strcpy(pi3, BN_bn2hex(Z));

	BN_free(r);
	BN_free(Z);
	BN_free(beta_1);
	BN_free(beta_0);
	BN_free(server_E);
	BN_free(alp);
	BN_free(BETA_0);
}
void Hash_g(char* num, BIGNUM* result) {
	BIGNUM* exp = BN_new();
	BN_hex2bn(&exp, num);
	// r = a ^ p mod m - > temp = g_0 ^ exp mod p 
	BN_mod_exp(result, g_0, exp, p, ctx);

	BN_free(exp);
}
