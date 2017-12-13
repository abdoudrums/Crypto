#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <openssl/md5.h>

///******************************************************************************** déclarations
enum Action {
		SANS_MODE = 0,
		CHIFFRER = 1,
		DECHIFFRER = 2
	};
char *nomBourrage = strdup("Bourrage-");
char *aesNomFichier = strdup("aes-");
bool  aParametres;
bool  aAction;
char *clef;
char *nomFichier;
char *fichierBourrage;
unsigned char resume_md5[MD5_DIGEST_LENGTH];

typedef unsigned char uchar;
uchar Mul_F256[256][256];
int Nr = 10, Nk = 4;
int longueur_de_la_clef_etendue = 176;
int longueur_de_la_clef = 16 ;
uchar State[16] ={
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
FILE *fichier;
FILE *fichier2;
uchar SBox[256] ={
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
uchar Iv[16];
uchar tkahbina[16];
uchar vecteur[16] ={
		0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01,
		0x01, 0x01, 0x02, 0x03, 0x03, 0x01, 0x01, 0x02
};
uchar W[240];
uchar K[16] ={
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
/********************************************************* TP B ***********************************************************************/
uchar Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
} ;
void RotWord(uchar tab[]){
    uchar c=tab[0];
    int i;
    for(i=1;i<4;i++)
        tab[i-1]=tab[i];
    tab[i-1]=c;
}
void SubWord(uchar tab[]){
  for(int i=0;i<4;i++)
    tab[i]=SBox[tab[i]];
}
void affiche_la_clef(uchar *clef, int longueur){

    printf("\n\n\t Rounds   [00] |=>  ");
    for (int i=0; i<longueur; i++)
        {
            printf ("%02X ", clef[i]);
            if(((i+1)%16 == 0 ) && ( i != 0) && i!= longueur-1 )
            printf("\n\t RoundKeys[%02X] |=>  ",(i+1)/16);
        }
    printf("\n");

}
void calcule_la_clef_etendue(uchar *K, int long_K, uchar *W, int long_W, int Nr, int Nk){
uchar tmp[4];
uchar Rcon_tmp[4];
uchar W_tmp[4];
/************************ Ligne 1,2 **********************/
for(int i=0; i<Nk;i++)
    for(int k=i*4; k<(i+1)*Nk; k++)
        W[k] = K[k];
/************************ Ligne 3  ***********************/
for(int i=Nk; i<4*(Nr+1); i++){
/************************ Ligne 4  ***********************/
for(int j=0;j<4; j++) tmp[j]=W[(i*4)-4+j];
/************************ Ligne 5  ***********************/
if((i%Nk)==0){
/************************ Ligne 6  ***********************/
    RotWord(tmp);
/************************ Ligne 7  ***********************/
    SubWord(tmp);
/************************ Ligne 8  ***********************/
    Rcon_tmp[0]=Rcon[(i/Nk)-1];
    for(int k=1;k<4;k++) Rcon_tmp[k]=0x00;
    for(int l=0;l<4;l++) tmp[l]=tmp[l]^Rcon_tmp[l];
}
/************************ Ligne 9,10  *********************/
else if( Nk >6 && (i%Nk)==4) SubWord(tmp);
/************************ Ligne 11  ***********************/
for(int l=0;l<4;l++) W_tmp[l]=W[((i-Nk)*4)+l];
for(int g=0;g<4;g++) tmp[g]=tmp[g]^W_tmp[g];
/************************ Ligne 12  ***********************/
for(int x=0;x<4;x++) W[(i*4)+x]=tmp[x];
}
}
uchar gmul(uchar a, uchar b) {
	uchar p = 0;
	uchar hi_bit_set;
	int i;
	for(i = 0; i < 8; i++) {
		if((b & 1) == 1)
			p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if(hi_bit_set == 0x80)
			a ^= 0x1b;
		b >>= 1;
	}
	return p;
}
void affiche_bloc_matriciel(uchar *M) {
    printf("\n");
	int i,j;
	printf(" Résultat:  0x");
	for(int i=0;i<16;i++) printf ("%02X", M[i]);
        printf("\n\n");
}
/********************************************************* TP C ***********************************************************************/
void SubBytes(){

	for(int v=0;v<16;v++)
		State[v] = SBox[State[v]];
};
void Inv_SubBytes(){

	for(int i=0;i<16;i++)
		for(uchar v=0x00;v<0x100;v++)
			if(SBox[v] == State[i])
			{
				State[i]=v;
				break;
			}
};
void ShiftRows(){
	int a,b,c;
	a = State[1];
	State[1] = State[5];
	State[5] = State[9];
	State[9] = State[13];
	State[13] = a;

	a = State[2];
	b = State[6];
	State[2] = State[10];
	State[6] = State[14];
	State[10] = a;
	State[14] = b;

	a = State[3];
	b = State[7];
	c = State[11];
	State[3] = State[15];
	State[7] = a;
	State[11] = b;
	State[15] = c;
};
void Inv_ShiftRows(){
	uchar a;
	a = State[13];
	State[13] = State[9];
	State[9] = State[5];
	State[5] = State[1];
	State[1] = a;

	a = State[2];
	State[2] = State[10];
	State[10] = a;

	a = State[15];
	State[15] = State[3];
	State[3] = State[7];
	State[7] = State[11];
	State[11] = a;

	a = State[6];
	State[6] = State[14];
	State[14] = a;
};
void MixColumns(){
	uchar b=0x00;
	uchar tmp[4];
	int i=0;
	int j=0;
	int k;
	int g=0;
	while(i<4){
		while(j<((i+1)*4)){
			tmp[j%4]=State[j];
			j++;
		}
		k=0;
		while(k<16)
		{
			b=gmul(tmp[k%4],vecteur[k])^b;
			if(((k+1)%4)==0)
			{
				State[g]=b;
				g++;
				b=0x00;
			}
			k++;
		}
		i++;
	}
};
void Inv_MixColumns(){

	int i,j,k;
	unsigned a=0x00;
	uchar ligne[4];
	uchar matrice[4][4] = {
			{0x0E, 0x0B, 0x0D, 0x09},
			{0x09, 0x0E, 0x0B, 0x0D},
			{0x0D, 0x09, 0x0E, 0x0B},
			{0x0B, 0x0D, 0x09, 0x0E}
	};
	for(k=0;k<4;k++){
		for(i=0;i<4;i++){
			for(j=0;j<4;j++){
				a = a ^ Mul_F256[matrice[i][j]][State[j+4*k]];
			}
			ligne[i] = a;
			a=0x00;
		}
		for(j=0;j<4;j++){
			State[j+4*k] = ligne[j];
		}
	}
};
void AddRoundKey(int r){

	for(int i=0;i<16;i++)
	{
		State[i]=State[i]^W[r*16+i];
	}
};
/******************************************************Chiffrement*********************************************************************/
void chiffrer(){
	AddRoundKey(0);
	for (int i = 1; i < Nr; i++) {
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(i);
	}
	SubBytes();
	ShiftRows();
	AddRoundKey(Nr);
}
/****************************************************Dechiffrement*********************************************************************/
void dechiffrer(){
	AddRoundKey(Nr);
	Inv_ShiftRows();
	Inv_SubBytes();
	for (int i = Nr-1; i > 0; i--) {
		AddRoundKey(i);
		Inv_MixColumns();
		Inv_ShiftRows();
		Inv_SubBytes();
	}
	AddRoundKey(0);
}
/*************************************************Effectuer le Bourrage****************************************************************/
int pkcs5(){
fichier = fopen(nomFichier, "rb");
strcat(nomBourrage, nomFichier);
fichier2 = fopen(nomBourrage, "wb");
if (fichier)
 	{
	 int i;
	 	fseek (fichier, 0, SEEK_END);
     	int size=ftell (fichier);
     	uchar buffer[size];
     	fseek (fichier, 0, SEEK_SET);
     	fread(buffer, size, 1, fichier);

 	if ((size%16)==0)
       {
       	int a = 16-(size%16);
        fwrite(buffer,size, 1, fichier2);
    for(int i=0;i<a;i++)
    tkahbina[i]=16;

    fwrite(tkahbina, 16, 1, fichier2);
    return 1;
		  }
	else if((size%16)!=0)
		{
		int a = 16-(size%16);
        fwrite(buffer,size, 1, fichier2);
    for(int i=0;i<a;i++)
     tkahbina[i]=a;

    fwrite(tkahbina, a, 1, fichier2);
		}
		fclose(fichier);
		fclose(fichier2);
		return 1;
 	}
else return 0;
}
/*****************************Le vecteur d'initialisation aléatoirement à chaque chiffrement*******************************************/
static void CreerIv(uchar*Iv){
	srand(time(NULL));

 		for(int i=0; i<16; i++)
        {
            if(i==4)
            {
                Iv[i]=tkahbina[0];
                i++;
            }
            Iv[i]=rand();
        }

}
/****************************************Fonction qui fait le XOR avec en entrée State*************************************************/
static void XorWithIv (uchar*State ){
  	for (int i = 0; i < 16; ++i)
 	 	{
    	State[i] ^= Iv[i];
  		}
}
void CBC_chiffrer(){
    CreerIv(Iv);
  fichier = fopen(nomBourrage, "rb");
  strcat(aesNomFichier, nomFichier);
	if (fichier){
    fichier2 = fopen(aesNomFichier, "wb");
    fwrite(Iv, 16, 1, fichier2 );
    for (int k=0; k<16; k++){
                }
	 	fseek (fichier, 0, SEEK_END);
     	int size=ftell (fichier);
     	uchar buffer[size];
     	 uchar m[size];
     	fseek (fichier, 0, SEEK_SET);
     	fread(buffer, size, 1, fichier);

    	for (int i = 0; i <(size/16)-1; i++){
    	for (int j=i*16; j<(i*16)+16; j++){
			State[j%16]=buffer[j];
		}
   		XorWithIv(State);
   		chiffrer();

   	 	for(int k=0;k<16;k++){
    		Iv[k] = State[k];
		}

		for (int b=i*16; b<(i*16)+16; b++){
			m[b] =State[b%16];
		}
     }
	  	fwrite(m, size, 1, fichier2 );
     	fclose (fichier);
     	fclose(fichier2);
   	}
}
/*****************************************Dechiffrement avec le mode opératoire CBC****************************************************/
int CBC_dechiffrer(){

  fichier = fopen(nomFichier, "rb");
  strcat(aesNomFichier, nomFichier);

	if (fichier)
	{
    fichier2 = fopen(aesNomFichier, "wb");
	 fseek (fichier, 0, SEEK_END);
     int size=ftell (fichier);
     uchar buffer1[size];
     fseek (fichier, 0, SEEK_SET);
     fread(buffer1, size, 1, fichier);
     size=size-16;
     uchar m2[size-tkahbina[0]];

     uchar c [16];
     uchar c2[size];


	 for (int k=0; k<16; k++){
            Iv[k]=buffer1[k];
                }
        int enigme=Iv[4];
     for (int k=16; k<(size+16); k++){
            c2[k-16]=buffer1[k];
                }
   		for (int i = 0; i <(size/16)-1; i++)
		{
	    	for (int j=i*16; j<(i*16)+16; j++)
			{
	    		c[j%16]=c2[j];
				State[j%16]=c2[j];
			}
			dechiffrer();
	   		XorWithIv(State);
	   		for(int k=0;k<16;k++)
			{
	    		Iv[k] = c[k];
			}
	   		int b;
			for (b=i*16; b<(i*16)+16 && b<(size-tkahbina[0]); b++)
			{
				m2[b] = State[b%16];
			}
     	}
	  	fwrite(m2, (size-enigme), 1, fichier2 );
     	fclose (fichier);
     	fclose(fichier2);
     	return 1;
	}
	else{
		return 0;
	}
}

unsigned char resumeMd5Clef(char* clef){
  MD5_CTX contexte;
  MD5_Init (&contexte);

  MD5_Update (&contexte, clef, strlen(clef));                // Digestion du morceau

  MD5_Final (resume_md5, &contexte);


  printf("\n La clef utilisée est: 0x");
  for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
    printf("%02x", resume_md5[i]);
    K[i]=resume_md5[i];
  }
    int long_de_la_clef = 16 ;
	int Nr, Nk;
	if (long_de_la_clef == 16){ Nr = 10; Nk = 4; }
	else if (long_de_la_clef == 24){ Nr = 12; Nk = 6; }
	else { Nr = 14; Nk = 8; }
	int long_de_la_clef_etendue = 4*(4*(Nr+1));
	calcule_la_clef_etendue(K, long_de_la_clef, W, long_de_la_clef_etendue, Nr, Nk);


}
/************************************fonctions de traitement  des parametres****************************************************/
void usage(void){
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "./AES -e|-d <nom du fichier> <clef>  \n");
  fprintf(stderr, "\n");
  fprintf(stderr, "-e | -d <nom du fichier>: lance le programme pour chiffrer (-e) ou dechiffrer (-d) un fichier ou un bloc nul avec la clef nulle ou une clef donnée par l'utilisateur \n");
  fprintf(stderr, "-h: afficher l'aide\n");
  exit(1);
}
static void pasDeParanetres(enum Action action){
	printf("\n le résultat du chiffrement du bloc nul avec la clef nulle");
	chiffrer();
	affiche_bloc_matriciel(State);
}
static void pasDeFichier(enum Action action){
  	if(action == CHIFFRER){
		printf("\n le résultat du chiffrement du bloc nul avec la clef nulle");
		chiffrer();
		affiche_bloc_matriciel(State);
	} else {
		printf("\n le résultat du dechiffrement du bloc nul avec la clef nulle");
		dechiffrer();
		affiche_bloc_matriciel(State);
	}
}
static void pasDeClef(enum Action action, char *nomFichier){
	if(action == CHIFFRER){
		int a=pkcs5();
		if(a==1){
			CBC_chiffrer();
			printf("\n Chiffrement de %s en %s \n\n",nomFichier,aesNomFichier);
    }else{
			printf("\n Le fichier n'existe pas desole \n\n");
		}
	}else{
	    char *copienomFichier=nomFichier;
	    int b=CBC_dechiffrer();
	    if(b==1){
      	printf("\n Déchiffrement de %s en ",copienomFichier);
				printf("%s \n\n",aesNomFichier);
      }else{
				printf("\n Le fichier n'existe pas desole \n\n");
			}
	}
}
static void traiterAvecClef(char *clef, enum Action action, char *nomFichier){
	resumeMd5Clef(clef);
	if(action == CHIFFRER){
		int a=pkcs5();
		if(a==1){
			CBC_chiffrer();
			printf("\n Chiffrement de %s en %s \n\n",nomFichier,aesNomFichier);
        }else{
			printf("\n Le fichier n'existe pas !! desole \n\n");
		}
	}else{
	    char *copienomFichier=nomFichier;
	    int b=CBC_dechiffrer();
	    if(b==1){
      	printf("\n Déchiffrement de %s en ",copienomFichier);
				printf("%s \n\n",aesNomFichier);
      }else{
			printf("\n Le fichier n'existe pas !! desole \n\n");
			}
	}
}
static void traiterParametres (char *nomFichier, enum Action action, char *clef){
  	if(!aParametres) {
		pasDeParanetres(action);
	} else if(nomFichier == '\0') {
		pasDeFichier(action);
	} else if(clef == '\0') {
		pasDeClef(action, nomFichier);
	} else if(clef != '\0'){
		traiterAvecClef(clef, action, nomFichier);
	}
}
int main (int argc, char** argv){

	for (int i=0 ; i<256; i++) {
		for (int j=0 ; j<256; j++) {
			Mul_F256[i][j] = gmul(i,j) ;
		}
	}

	int long_de_la_clef = 16 ;
	int Nr, Nk;
	if (long_de_la_clef == 16){ Nr = 10; Nk = 4; }
	else if (long_de_la_clef == 24){ Nr = 12; Nk = 6; }
	else { Nr = 14; Nk = 8; }
	int long_de_la_clef_etendue = 4*(4*(Nr+1));

	calcule_la_clef_etendue(K, long_de_la_clef, W, long_de_la_clef_etendue, Nr, Nk);

	/*************************PAS TOUCHER******************************/
	int option;
	aParametres = true;
	enum Action action = SANS_MODE;

	if (argc == 1){
		aParametres = false;
	}

/********************************Traiter les options des lignes de commandes***********************/
	while((option = getopt(argc, argv, "edh")) > 0) {
		switch(option) {
		  case 'e':
			action = CHIFFRER;
			break;
		  case 'd':
			action = DECHIFFRER;
			break;
		  default:
			usage();
		}
	}

	nomFichier = argv[2];
	clef = argv[3];

	traiterParametres(nomFichier, action, clef);
/********************************Traiter les options des lignes de commandes***********************/

	return EXIT_SUCCESS;
}
