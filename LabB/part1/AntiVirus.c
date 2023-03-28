#include <stdio.h>
#include <stdlib.h>

typedef struct virus{
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
}virus;

virus* readVirus(FILE* file){
    virus *v;
    char virusBuff[16];
    fread(virusBuff, 2, 1, file);
    v->SigSize = (int) virusBuff;
    fread(v->virusName, 16, 1, file);
    fread(v->sig, 5, 1, file);
    return v;
}

void printVirus(virus* virus, FILE* output){
    // FILE* file;
    // // char vName = virus->virusName;
    // // short vSize = virus->SigSize;
    // // char vSig = virus->sig;
    // file = fopen(output, "w");
    // if (file == NULL){
    //     printf("ERROR! No such file!");
    //     exit(1);
    // }

    fprintf(output, "%s", virus->virusName);
    fprintf(output, "%d", virus->SigSize);
    fprintf(output, "%02X", virus->sig);
    //fclose(file);
}

int main(int argc, char **argv){
    if (argc < 2){
        printf("%s", "Not Enogh Arguments!\n");
        exit(0);
    }
    FILE * file = fopen(argv[1], "r");
    if (file == NULL){
        printf("%s", "Failed to open output file!\n");
        exit(0);
    }
    virus * v = readVirus(file);
    printVirus(v, file);
    return 0;
    
}
