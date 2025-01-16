# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <openssl/aes.h>

unsigned char* encrypt_with_AES(unsigned char *input, long size) {
    // AES_KEY encryptKey;
    unsigned char key[32] = {0}; // 256-bit key for AES
    // AES_set_encrypt_key(key, 256, &encryptKey);

    unsigned char *output = malloc(size);
    // AES_encrypt(input, output, &encryptKey);

    return output;
    // Now write the encrypted data to a file or output buffer
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
    } else {
        // If there is no dot (no extension), handle that case
        perror("Error: No extension found in input path");
    }

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
    fread(buffer, 1, fileSize, inputFile);
    fclose(inputFile);

    printf(buffer);

    int choice;
    printf("Choose encryption algorithm:\n");
    printf("1. RC4\n");
    printf("2. AES\n");
    printf("3. DES\n");
    printf("4. 3-DES\n");
    printf("5. Salsa20\n");
    scanf("%d", &choice);


    unsigned char *outputBuffer = NULL;

    switch(choice) {
        case 1: 
            // encrypt_with_RC4(buffer, fileSize);
            outputFileNamer(input_path, "RC4", output_path);
            break;
        case 2: 
            outputBuffer = encrypt_with_AES(buffer, fileSize);
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
    }

   FILE *outputFile = fopen(output_path, "wb");
    if (!outputFile) {
        perror("Error opening output file");
        return 1;
    }

    fwrite(outputBuffer, 1, fileSize, outputFile);
    fclose(outputFile);

}