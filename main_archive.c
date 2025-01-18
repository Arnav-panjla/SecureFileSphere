#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>



#define STATE_ARRAY_SIZE 128


unsigned char* key = "password!@#$^&*"; // 128-bit key for RC4

// RC4 state initialization
void initialize_state(unsigned char state[], const unsigned char key[], int key_length) {
    int i, j = 0;
    unsigned char temp;
    
    // Initialize state array
    for (i = 0; i < STATE_ARRAY_SIZE; i++) {
        state[i] = i;
    }
    
    // Key scheduling algorithm (KSA)
    for (i = 0; i < STATE_ARRAY_SIZE; i++) {
        j = (j + state[i] + key[i % key_length]) % STATE_ARRAY_SIZE;
        // Swap state[i] and state[j]
        temp = state[i];
        state[i] = state[j];
        state[j] = temp;
    }
}


// RC4 encryption/decryption function that returns a buffer
unsigned char* rc4_crypt(const unsigned char* input_buffer, size_t input_length, 
                        const unsigned char key[], int key_length, size_t* output_length) {
    unsigned char state[STATE_ARRAY_SIZE];
    unsigned char* output_buffer;
    int i = 0, j = 0;
    unsigned char temp;
    size_t pos;
    
    // Allocate output buffer
    output_buffer = (unsigned char*)malloc(input_length);
    if (output_buffer == NULL) {
        *output_length = 0;
        return NULL;
    }
    *output_length = input_length;
    
    // Initialize RC4 state
    initialize_state(state, key, key_length);
    
    // Process each byte of the input buffer
    for (pos = 0; pos < input_length; pos++) {
        // Generate pseudorandom byte
        i = (i + 1) % STATE_ARRAY_SIZE;
        j = (j + state[i]) % STATE_ARRAY_SIZE;
        
        // Swap state[i] and state[j]
        temp = state[i];
        state[i] = state[j];
        state[j] = temp;
        
        // XOR input byte with generated key byte
        output_buffer[pos] = input_buffer[pos] ^ 
                            state[(state[i] + state[j]) % STATE_ARRAY_SIZE];
    }
    
    return output_buffer;
}


void outputFileNamer(char *input_path, char *encryption_type, char *output_path) {

    // Find the last occurrence of '.' in input_path (the extension separator)
    const char *dot = strrchr(input_path, '.');
    
    if (dot != NULL) {
        // Copy the part before the '.' (the base filename)
        size_t len = dot - input_path; // Length of the base filename
        strncpy(output_path, input_path, len); // Copy the base filename part
        output_path[len] = '\0'; // Null-terminate the string
        
        // Append the desired suffix and extension
        strcat(output_path, "_encrypt_");
        strcat(output_path, encryption_type);
        strcat(output_path, ".txt");
        output_path[strlen(output_path)] = '\0';  // Make sure it's null-terminated

    } else {
        // If there is no dot (no extension), handle that case
        perror("Error: No extension found in input path");
    }

}

unsigned char* aes_encrypt(const unsigned char *key, const unsigned char *input_buffer, size_t length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating EVP_CIPHER_CTX.\n");
        return NULL;
    }

    // Initialize the encryption operation (AES 128-bit ECB mode)
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        fprintf(stderr, "Error initializing AES encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Padding is automatically handled in ECB mode, but we still need to compute the padded length
    int padded_length = (length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
    unsigned char *output_buffer = (unsigned char *)malloc(padded_length);
    if (!output_buffer) {
        fprintf(stderr, "Memory allocation failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int out_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, output_buffer, &out_len, input_buffer, length)) {
        fprintf(stderr, "Error during AES encryption update.\n");
        free(output_buffer);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, output_buffer + out_len, &final_len)) {
        fprintf(stderr, "Error during final AES encryption step.\n");
        free(output_buffer);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    out_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    // Resize the output buffer to the actual encrypted data length
    output_buffer = realloc(output_buffer, out_len);
    return output_buffer;
}

int main() {
    char input_path[100];
    char output_path[100];
    char line_buffer[1000];

    printf("Enter the path of the file to be encrypted: ");
    scanf("%s", input_path);

    FILE *inputFile = fopen(input_path, "rb");
    if (!inputFile) {
        perror("Error opening file");
        return 1;
    }

    fseek(inputFile, 0, SEEK_END);
    long fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    unsigned char *buffer = malloc(fileSize);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(inputFile);
        return 1;
    }
    fread(buffer, 1, fileSize, inputFile);
    fclose(inputFile);

    printf("Choose encryption algorithm:\n");
    printf("1. RC4\n");
    printf("2. AES\n");
    printf("3. DES\n");
    printf("4. 3-DES\n");
    printf("5. Salsa20\n");
    int choice;
    scanf("%d", &choice);

    unsigned char *outputBuffer = NULL;
    size_t output_length;

    switch(choice) {
        case 1: 
            outputBuffer = rc4_crypt(buffer, fileSize, key, strlen(key), &output_length);
            outputFileNamer(input_path, "RC4", output_path);
            break;
        case 2: 
            outputBuffer = aes_encrypt(key, buffer, fileSize);
            outputFileNamer(input_path, "AES", output_path);
            break;
        case 3: 
            // encrypt_with_DES(buffer, fileSize);
            outputFileNamer(input_path, "DES", output_path);
            break;
        case 4: 
            // encrypt_with_3DES(buffer, fileSize);
            outputFileNamer(input_path, "3DES", output_path);
            break;
        case 5: 
            // encrypt_with_Salsa20(buffer, fileSize);
            outputFileNamer(input_path, "Salsa20", output_path);
            break;
        default:
            printf("Invalid choice.\n");
            return 1;
    }

    FILE *outputFile = fopen(output_path, "wb");
    if (!outputFile) {
        perror("Error opening output file");
        return 1;
    }

    if (outputBuffer) {
        fwrite(outputBuffer, 1, output_length, outputFile);
        free(outputBuffer); // Don't forget to free memory after use
    }

    fclose(outputFile);
}
