#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

#define SGX_ECP256_KEY_SIZE   32
#define SGX_AESCTR_KEY_SIZE   16

int enclave_secret = 1337;

// https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_tcrypto.h

// ENCLAVE PARAMETERS
sgx_ec256_private_t private_param;
sgx_ec256_public_t public_param;
sgx_ecc_state_handle_t ecc_param;

//OTHER KEY PARAMS
sgx_ec256_dh_shared_t shared_key_param;
sgx_aes_ctr_128bit_key_t ctr_key;

uint8_t IV[SGX_AESCTR_KEY_SIZE];

//state variable
uint8_t state = 0;

// Challenge numbers
uint8_t a;
uint8_t b;


int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

/***********************************************
// 2. BEGIN: Generate key pair enclave A
***********************************************/

// https://github.com/intel/linux-sgx/blob/master/sdk/tlibcrypto/sgxssl/sgx_ecc256.cpp
// https://github.com/yuyuany/linux-sgx/blob/master/sdk/tkey_exchange/tkey_exchange.cpp
// https://stackoverflow.com/questions/42015168/sgx-ecc256-create-key-pair-fail (faced this error)
sgx_status_t create_ecc(sgx_ec256_public_t *public_key) {

  sgx_status_t ret_status = sgx_ecc256_open_context(&ecc_param);
  if (ret_status != SGX_SUCCESS)
    return ret_status;

  ret_status = sgx_ecc256_create_key_pair(&private_param, &public_param, ecc_param);
  if (ret_status != SGX_SUCCESS)
    return ret_status;

  for (int j = 0; j < SGX_ECP256_KEY_SIZE; j++){
    public_key->gx[j] = public_param.gx[j];
    public_key->gy[j] = public_param.gy[j];
  }

  return SGX_SUCCESS;
}

/***********************************************
// 2. END: Generate key pair enclave A
***********************************************/

/***********************************************
// 3. BEGIN: Create DH shared secret enclave A
***********************************************/
sgx_status_t derive_shared_key(sgx_ec256_public_t *public_key) {

  sgx_status_t ret_status;

  //Compute DH shared key by using own private and public of other app
  ret_status = sgx_ecc256_compute_shared_dhkey(&private_param, public_key, &shared_key_param, ecc_param);
  if (ret_status != SGX_SUCCESS)
    return ret_status;

  //the function derives the ecc256 key, and create the ctr 128 bit keys
  //by taking the first half of the ecc key
  for (int j = 0; j < SGX_AESCTR_KEY_SIZE; j++){
    ctr_key[j] = shared_key_param.s[j];
  }

  // Static all 0 IV of 16 bytes
  //memset(IV, 0, 16); 

  //Initialize IV vector and save it into IV
  ret_status = sgx_read_rand(IV, SGX_AESCTR_KEY_SIZE);
  if (ret_status != SGX_SUCCESS)
    return ret_status;

  return SGX_SUCCESS;
}

/***********************************************
// 3. END: Create DH shared secret enclave A
***********************************************/

/****************************************************************
// 3. BEGIN: SEND PSK from A to B and verify what you get from B
*****************************************************************/

// Encrypt PSK to send to B
sgx_status_t get_encrypted_message_psk(uint8_t* C){
  sgx_status_t ret_status;
  // uint8_t* PSK_A = (uint8_t*) "I AM ALICE";
  // ret_status = sgx_aes_ctr_encrypt(&ctr_key, (const uint8_t*) PSK_A, (uint32_t)sizeof(uint8_t), IV, 1, C);

  // size of PSK is 11 bytes (hardcoded this in the .edl and named pipe)
  char PSK_A[] = "I AM ALICE";
  uint8_t *p_src;
  uint32_t p_len = sizeof(PSK_A);
  p_src = (uint8_t *)malloc(p_len);
  memcpy(p_src, PSK_A, p_len);

  ret_status = sgx_aes_ctr_encrypt(&ctr_key, p_src, p_len, IV, 1, C);
  return ret_status;
}

// Utility function
void fetch_iv(uint8_t* iv){
  for (int j = 0; j <SGX_AESCTR_KEY_SIZE; j++){
    iv[j] = IV[j];
  }
}

// Decrypt the received PSK from B
sgx_status_t get_decrypted_message_psk(uint8_t* C, uint8_t* iv){
  uint8_t *updated_state = (uint8_t*) &updated_state;
  sgx_status_t ret_status;

  char PSK_A[] = "I AM ALICE";
  uint32_t p_len = sizeof(PSK_A);
  //ret_status = sgx_aes_ctr_decrypt(&ctr_key, C, (uint32_t)sizeof(uint8_t), iv, 1, updated_state);
  ret_status = sgx_aes_ctr_decrypt(&ctr_key, C, p_len, iv, 1, updated_state);

  if (ret_status != SGX_SUCCESS)
      return ret_status;

  return ret_status;
}

/*********************************************************
// 4. BEGIN: Enclave A generates the challenge to be sent
**********************************************************/

// create the challenge in Enclave A
sgx_status_t get_challenge(uint8_t *challenge){
  sgx_status_t ret_status;

  sgx_read_rand(&a, 1);
  sgx_read_rand(&b, 1);

  uint8_t ab[3];
  uint8_t *ptr_ab = (uint8_t*) &ab;

  // Serialize as consecutive for writing a and b
  // to the shared file
  memcpy(ptr_ab, &a, 1);
  ptr_ab++;
  memcpy(ptr_ab, &b, 1);

  ret_status = sgx_aes_ctr_encrypt(&ctr_key, (const unsigned char*) &ab, 3, IV, 1, challenge);
  return ret_status;
}

/*********************************************************
// 4. END: Enclave A generates the challenge to be sent
**********************************************************/

/***********************************************************
// 5. BEGIN: Enclave A decrypts the challenge and verifies
************************************************************/

// Check received from Enclave B
sgx_status_t check_response(uint8_t *response, uint8_t* iv){
  sgx_status_t ret_status;

  uint8_t response_recvd[3];
  uint8_t *ptr_response_recvd = (uint8_t *) &response_recvd;

  ret_status = sgx_aes_ctr_decrypt(&ctr_key, response, 16, iv, 1, ptr_response_recvd);

  int actual_value = static_cast<int>(a) + static_cast<int>(b);
  int int_response = atoi((char *) ptr_response_recvd);

  if (actual_value != int_response){
    printf("Response didn't match expected value...\n");
    ret_status = SGX_ERROR_INVALID_PARAMETER;
    return ret_status;
  }
  
  return ret_status;

}

/***********************************************************
// 5. END: Enclave A decrypts the challenge and verifies
************************************************************/

sgx_status_t printSecret()
{
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave A.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}


