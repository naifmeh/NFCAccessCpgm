#ifdef HAVE_CONFIG_H
# include "config.h"
#endif 

#include <err.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <my_global.h>
#include <mysql.h>

#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include "../utils/nfc-utils.h"

#define MAX_DEVICES 5

static nfc_device *pnd = NULL;

static void print_usage(const char *argv[]) {
	printf("Utilisation: %s [OPTIONS]\n",argv[0]);
	printf("Options:\n");
	printf("\t-h\tPrint this help message.\n");
    printf("\t-v\tSet verbose display.\n");
    printf("\t-i\tAllow intrusive scan.\n");
}
 void
print_hex(const uint8_t *pbtData, const size_t szLen)
{
  size_t  szPos;

  for (szPos = 0; szPos < szLen; szPos++) {
    printf("%02x  ", pbtData[szPos]);
  }
  printf("\n");

}
int mysql_exec_sql(MYSQL *mysql,char *query) {
	if(strlen(query)>0)
		return mysql_real_query(mysql,query,strlen(query));
	return -1;
}
uint8_t* hexstr_hex(char* str){
 	size_t i;
 	char *pos = str;
 	uint8_t hex[strlen(str)/2];

 	for(i=0;i<strlen(str);i++) {
 		sscanf(pos,"%2hhx",&hex[i]);
 		pos+=2;
 	}	
 	return hex;
}

const char* hexToStr(uint8_t* hex,size_t len) {
	uint8_t* octet = (uint8_t*) hex;
	int i=0;
	char hexa[len];
	char hexstring[20] = "";

	while(i<len) {
		sprintf(hexa,"%02x",octet[i]);
		strcat(hexstring,hexa);
		//printf("%02x",octet[i++]);
		//fflush(stdout);
		i++;
	}
	char *str = malloc(sizeof(char)*len+1);

	hexstring[19] = '\0';
	str = strdup(hexstring);
	return str;
}

//TRANSMIT APDU COMMANDS AND READ APDU RESPONSES
int CardTransmit(nfc_device *pnd,uint8_t *capdu,size_t capdulen,
	uint8_t *rapdu,size_t *rapdulen) {
	int res;
	size_t szPos;
	printf("=> ");
	for(szPos=0;szPos<capdulen;szPos++) {
		printf("%02x ",capdu[szPos]);
	}
	printf("\n");
	if((res = nfc_initiator_transceive_bytes(pnd,capdu,capdulen,rapdu,*rapdulen,500))
		< 0) 
		return -1;
	else {
		*rapdulen = (size_t) res;
		printf("<= ");
		for(szPos=0;szPos< *rapdulen;szPos++) {
			printf("%02x ",rapdu[szPos]);
		}
		printf("\n");
		return 0;
	}
}




//-----------------------------------------------
int main(int argc, const char *argv[]) {
	const char *acLibnfcVer;
	size_t i;
	bool verbose = false;

	nfc_context *context;
	nfc_target nt;
	int arg=1;
	for(arg=1;arg<argc;arg++) {
		if(0 == strcmp(argv[arg],"-h")) {
			print_usage(argv);
			exit(EXIT_SUCCESS);
		}
		else if(0 == strcmp(argv[arg],"-v")){
			verbose = true;

		}
		else if(0 == strcmp(argv[arg],"-i")) {
			setenv("LIBNFC_INTRUSIVE_SCAN","yes",1);
		}
		else {
			ERR("%s not supported",argv[arg]);
			print_usage(argv);
			exit(EXIT_FAILURE);
		}
	}

	nfc_init(&context);
	if(!context) {
		ERR("Impossible d\'initialiser libnfc (malloc impo)\n");
		exit(EXIT_FAILURE);
	}

	acLibnfcVer = nfc_version();
	printf("%s utilise libnfc %s\n",argv[0],acLibnfcVer);

	nfc_connstring connstring[MAX_DEVICES];

	size_t szDevicesFound = nfc_list_devices(context,connstring,MAX_DEVICES);

	if(szDevicesFound == 0) {
		printf("No nfc devices found\n");
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	printf("%d NFC trouvés :\n",(int)szDevicesFound);
	char  *strinfo = NULL;
	
	for(i=0;i<szDevicesFound;i++) {
		pnd = nfc_open(context,NULL);
		if(nfc_initiator_init(pnd) < 0) {
			nfc_perror(pnd,"nfc_initiator_init");
			exit(EXIT_FAILURE);
		}
		if(pnd) {
			printf("- %s:\n %s\n",nfc_device_get_name(pnd),
				nfc_device_get_connstring(pnd));
			const nfc_modulation nmMifare = {
				.nmt = NMT_ISO14443A,
				.nbr = NBR_106
			};

			printf("EN recherche de target ...\n");
			while(nfc_initiator_select_passive_target(pnd,nmMifare,NULL,0,&nt) <= 0);
			printf("Target trouvé \n");
            printf("NFC TAG(Norme ISO14443A :\n");
            printf("\tATQA(SENS_RES): ");
            print_hex(nt.nti.nai.abtAtqa,2);
            printf("\tUID: ");
            print_hex(nt.nti.nai.abtUid,nt.nti.nai.szUidLen);

			
            MYSQL mysql;
            if(!mysql_init(&mysql)) exit(EXIT_FAILURE);

            if(!mysql_real_connect(&mysql,"127.0.0.1","root","test",NULL,3307,NULL,0)){
            	printf("Database connection failed... aborting\n");
            	exit(EXIT_FAILURE);
            }

            const char* hexstr = hexToStr(nt.nti.nai.abtUid,nt.nti.nai.szUidLen);
            
            mysql_exec_sql(&mysql,"USE authaccess");
            mysql_query(&mysql,"SELECT * FROM authUsers");
            MYSQL_RES *result = mysql_store_result(&mysql);
			if(!result) {
				printf("ERROR RETRIEVING\n");

			}
			int num_f = mysql_num_fields(result);

			MYSQL_ROW row;
			MYSQL_FIELD *field;
			int i,flag=0,indice=-1,j=0;
			while((row = mysql_fetch_row(result))) {
	
 
				for(j=0;j<strlen(row[1]);j++){
					row[1][j] = tolower(row[1][j]);
				}

				if(strcmp((char*)row[1],hexstr) == 0){
					flag=1;
					indice=i;
					printf("ACESS GRANTED %s %s \n",(char*)row[2],(char*) row[3]);
				}

			}
			if(flag == 0) {
				printf("ACCESS REFUSED \n");
				exit(EXIT_FAILURE);
			}

			
			
			

			if(verbose) {
				if(nfc_device_get_information_about(pnd,&strinfo) >=0){
					printf("%s",strinfo);
					nfc_free(strinfo);
				}
			}
			nfc_close(pnd);
		} else {
			printf("Impo d\'ouvrir %s\n",connstring[i]);
		}
	
	mysql_free_result(result);
	mysql_close(&mysql);	
	nfc_exit(context);
	exit(EXIT_SUCCESS);


	return 0;

}