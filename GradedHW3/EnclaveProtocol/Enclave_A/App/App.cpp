#include <stdio.h>
#include <cstdio>
#include <string.h>
#include <assert.h>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "sgx_tcrypto.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

# define SGX_ECP256_KEY_SIZE             32
#define SEND  0
#define SEND_AND_CLOSE  1
#define CLOSE 2


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 1;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}



/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

// Write the public key to the shared file system (named pipe)
// https://www.geeksforgeeks.org/named-pipe-fifo-example-c-program/

void send_public_key(sgx_ec256_public_t public_key){
  int fd;
  const char *myfifo = "/tmp/myfifo";
  mkfifo(myfifo, 0666);
  fd = open(myfifo, O_WRONLY);

  write(fd, public_key.gx, SGX_ECP256_KEY_SIZE);
  write(fd, public_key.gy, SGX_ECP256_KEY_SIZE);

  close(fd);
}

sgx_ec256_public_t receive_public_key(){
  int fd;
  const char *myfifo = "/tmp/myfifo";
  mkfifo(myfifo, 0666);
  fd = open(myfifo,O_RDONLY);

  sgx_ec256_public_t public_key;
  read(fd, public_key.gx, SGX_ECP256_KEY_SIZE);
  read(fd, public_key.gy, SGX_ECP256_KEY_SIZE);

  close(fd);

  return public_key;
}


void encrypt_and_sendC(){
  u_int8_t C;
  u_int8_t IV[16];
  
  sgx_status_t sgx_stat;
  fetch_iv(global_eid, IV);
  
  sgx_status_t send_status;
  // Send PSK_A from A in form of C
  send_status = get_encrypted_message(global_eid, &sgx_stat, &C);

  if (send_status == SGX_SUCCESS)
    printf("Sending PSK_A worked...\n");
  else{
    printf("Sending PSK_A failed...\n");
    print_error_message(send_status);
  }
  
  int fd;
  const char *myfifo = "/tmp/myfifo_pska";
  mkfifo(myfifo, 0666);
  fd = open(myfifo, O_WRONLY);

  write(fd, &C, sizeof(u_int8_t));
  write(fd, IV, 16 * sizeof(u_int8_t));

  close(fd);
}

void receive_and_checkC(){
  int fd;
  const char * myfifo = "/tmp/myfifo_pskb";
  mkfifo(myfifo, 0666);
  fd = open(myfifo, O_RDONLY);

  u_int8_t C;
  u_int8_t IV[16];

  read(fd, &C, sizeof(u_int8_t));
  read(fd, IV, 16 * sizeof(u_int8_t));
  
  close(fd);

  sgx_status_t sgx_stat;
  sgx_status_t ret_status = get_decrypted_message(global_eid, &sgx_stat, &C, IV);

  if (ret_status != SGX_SUCCESS) {
    printf("Decrypting the message didn't work...\n");
    print_error_message(ret_status);
  }
  else
    printf("Decrypting message of PSK_B worked...\n");

}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("FAILED: Impossible initializing enclave, exiting  ...\n");
        return -1;
    }

    printf("Enclave creation sucessful....\n");

    sgx_ec256_public_t public_key;

    sgx_status_t enclave_status;
    sgx_status_t sgx_status;

    //Initializing ECC parameters inside the enclave
    enclave_status = create_ecc(global_eid, &sgx_status, &public_key);

    if (enclave_status == SGX_SUCCESS && sgx_status == SGX_SUCCESS)
      printf("ECC creation succeeded...\n");
    else {
      printf("ECC creation failed...\n");
      print_error_message(sgx_status);
      print_error_message(enclave_status);
    }

    // 1. BEGIN : SEND and RECEIVE public key App_A

    //Sending public key from AppA
    send_public_key(public_key);
    printf("Sent public key to AppB \n");

    //Receiving public key from App2
    sgx_ec256_public_t appA_public_key;
    appA_public_key = receive_public_key();
    printf("Received public key from AppB \n");

    //Derive DH shared key and initialize IV on the enclave
    sgx_status = derive_shared_key(global_eid, &enclave_status, &appA_public_key);
    if (enclave_status == SGX_SUCCESS && sgx_status == SGX_SUCCESS)
      printf("Computing shared key and IV worked...\n");
    else {
      printf("Computing shared key and IV didn't work...\n");
      print_error_message(sgx_status);
      print_error_message(enclave_status);
    }

    // Send PSK_A to AppB
    encrypt_and_sendC();

    // Receive PSK_B from AppB
    receive_and_checkC();

    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();

    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();

    printSecret(global_eid, &sgx_status);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("From App: Enclave destroyed\n");
    return 0;
}
