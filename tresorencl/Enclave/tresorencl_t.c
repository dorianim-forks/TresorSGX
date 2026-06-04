#include "tresorencl_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_enclInitCrypto_t {
	char ms_algorithm;
	unsigned char* ms_key;
	size_t ms_key_len;
} ms_enclInitCrypto_t;

typedef struct ms_enclInitSealedCrypto_t {
	uint32_t ms_retval;
	char ms_algorithm;
	unsigned char* ms_key;
	int ms_key_len;
	unsigned char* ms_buf;
	int ms_buf_len;
	int* ms_seal_len;
} ms_enclInitSealedCrypto_t;

typedef struct ms_enclEncrypt_t {
	unsigned char* ms_in;
	size_t ms_in_len;
	unsigned char* ms_out;
	size_t ms_out_len;
} ms_enclEncrypt_t;

typedef struct ms_enclDecrypt_t {
	unsigned char* ms_in;
	size_t ms_in_len;
	unsigned char* ms_out;
	size_t ms_out_len;
} ms_enclDecrypt_t;

typedef struct ms_enclavePrintf_t {
	const char* ms_string;
} ms_enclavePrintf_t;

typedef struct ms_enclavePrintInt_t {
	const int* ms_num;
} ms_enclavePrintInt_t;

typedef struct ms_enclavePrintHex_t {
	const char* ms_output;
	int ms_len;
} ms_enclavePrintHex_t;

static sgx_status_t SGX_CDECL sgx_enclInitCrypto(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclInitCrypto_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclInitCrypto_t* ms = SGX_CAST(ms_enclInitCrypto_t*, pms);
	ms_enclInitCrypto_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclInitCrypto_t), ms, sizeof(ms_enclInitCrypto_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_key = __in_ms.ms_key;
	size_t _tmp_key_len = __in_ms.ms_key_len;
	size_t _len_key = _tmp_key_len;
	unsigned char* _in_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	enclInitCrypto(__in_ms.ms_algorithm, _in_key, _tmp_key_len);

err:
	if (_in_key) free(_in_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclInitSealedCrypto(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclInitSealedCrypto_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclInitSealedCrypto_t* ms = SGX_CAST(ms_enclInitSealedCrypto_t*, pms);
	ms_enclInitSealedCrypto_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclInitSealedCrypto_t), ms, sizeof(ms_enclInitSealedCrypto_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_key = __in_ms.ms_key;
	int _tmp_key_len = __in_ms.ms_key_len;
	size_t _len_key = _tmp_key_len;
	unsigned char* _in_key = NULL;
	unsigned char* _tmp_buf = __in_ms.ms_buf;
	int _tmp_buf_len = __in_ms.ms_buf_len;
	size_t _len_buf = _tmp_buf_len;
	unsigned char* _in_buf = NULL;
	int* _tmp_seal_len = __in_ms.ms_seal_len;
	size_t _len_seal_len = sizeof(int);
	int* _in_seal_len = NULL;
	uint32_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);
	CHECK_UNIQUE_POINTER(_tmp_seal_len, _len_seal_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_seal_len != NULL && _len_seal_len != 0) {
		if ( _len_seal_len % sizeof(*_tmp_seal_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_seal_len = (int*)malloc(_len_seal_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_seal_len, 0, _len_seal_len);
	}
	_in_retval = enclInitSealedCrypto(__in_ms.ms_algorithm, _in_key, _tmp_key_len, _in_buf, _tmp_buf_len, _in_seal_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_buf) {
		if (memcpy_verw_s(_tmp_buf, _len_buf, _in_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_seal_len) {
		if (memcpy_verw_s(_tmp_seal_len, _len_seal_len, _in_seal_len, _len_seal_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_key) free(_in_key);
	if (_in_buf) free(_in_buf);
	if (_in_seal_len) free(_in_seal_len);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclEncrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclEncrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclEncrypt_t* ms = SGX_CAST(ms_enclEncrypt_t*, pms);
	ms_enclEncrypt_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclEncrypt_t), ms, sizeof(ms_enclEncrypt_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_in = __in_ms.ms_in;
	size_t _tmp_in_len = __in_ms.ms_in_len;
	size_t _len_in = _tmp_in_len;
	unsigned char* _in_in = NULL;
	unsigned char* _tmp_out = __in_ms.ms_out;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out = _tmp_out_len;
	unsigned char* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);
	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in != NULL && _len_in != 0) {
		if ( _len_in % sizeof(*_tmp_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_in = (unsigned char*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in, _len_in, _tmp_in, _len_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (unsigned char*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}
	enclEncrypt(_in_in, _tmp_in_len, _in_out, _tmp_out_len);
	if (_in_out) {
		if (memcpy_verw_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_in) free(_in_in);
	if (_in_out) free(_in_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclDecrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclDecrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclDecrypt_t* ms = SGX_CAST(ms_enclDecrypt_t*, pms);
	ms_enclDecrypt_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclDecrypt_t), ms, sizeof(ms_enclDecrypt_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_in = __in_ms.ms_in;
	size_t _tmp_in_len = __in_ms.ms_in_len;
	size_t _len_in = _tmp_in_len;
	unsigned char* _in_in = NULL;
	unsigned char* _tmp_out = __in_ms.ms_out;
	size_t _tmp_out_len = __in_ms.ms_out_len;
	size_t _len_out = _tmp_out_len;
	unsigned char* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);
	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in != NULL && _len_in != 0) {
		if ( _len_in % sizeof(*_tmp_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_in = (unsigned char*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in, _len_in, _tmp_in, _len_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (unsigned char*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}
	enclDecrypt(_in_in, _tmp_in_len, _in_out, _tmp_out_len);
	if (_in_out) {
		if (memcpy_verw_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_in) free(_in_in);
	if (_in_out) free(_in_out);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_enclInitCrypto, 0, 0},
		{(void*)(uintptr_t)sgx_enclInitSealedCrypto, 0, 0},
		{(void*)(uintptr_t)sgx_enclEncrypt, 0, 0},
		{(void*)(uintptr_t)sgx_enclDecrypt, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][4];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL enclavePrintf(const char* string)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_string = string ? strlen(string) + 1 : 0;

	ms_enclavePrintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_enclavePrintf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(string, _len_string);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (string != NULL) ? _len_string : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_enclavePrintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_enclavePrintf_t));
	ocalloc_size -= sizeof(ms_enclavePrintf_t);

	if (string != NULL) {
		if (memcpy_verw_s(&ms->ms_string, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_string % sizeof(*string) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, string, _len_string)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_string);
		ocalloc_size -= _len_string;
	} else {
		ms->ms_string = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL enclavePrintInt(const int* num)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_num = sizeof(int);

	ms_enclavePrintInt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_enclavePrintInt_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(num, _len_num);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (num != NULL) ? _len_num : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_enclavePrintInt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_enclavePrintInt_t));
	ocalloc_size -= sizeof(ms_enclavePrintInt_t);

	if (num != NULL) {
		if (memcpy_verw_s(&ms->ms_num, sizeof(const int*), &__tmp, sizeof(const int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_num % sizeof(*num) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, num, _len_num)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_num);
		ocalloc_size -= _len_num;
	} else {
		ms->ms_num = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL enclavePrintHex(const char* output, int len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_output = len;

	ms_enclavePrintHex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_enclavePrintHex_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(output, _len_output);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (output != NULL) ? _len_output : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_enclavePrintHex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_enclavePrintHex_t));
	ocalloc_size -= sizeof(ms_enclavePrintHex_t);

	if (output != NULL) {
		if (memcpy_verw_s(&ms->ms_output, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_output % sizeof(*output) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, output, _len_output)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_output);
		ocalloc_size -= _len_output;
	} else {
		ms->ms_output = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

