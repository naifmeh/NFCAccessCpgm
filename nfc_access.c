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
			printf("UID : ");
			print_hex(nt.nti.nai.abtUid,nt.nti.nai.szUidLen);
			uint8_t capdu[264];
			size_t capdulen;
			uint8_t rapdu[264];
			size_t rapdulen;

			memcpy(capdu, "\xFF\xCA\x00\x00\x00\xF0\x39\x41\x48\x14\x81\x00",12);
			capdulen = 12;
			rapdulen = sizeof(rapdu);
			if(CardTransmit(pnd,capdu,capdulen,rapdu, &rapdulen)<0) {
				exit(EXIT_FAILURE);
			}
			if(rapdulen<2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00) 
				exit(EXIT_FAILURE);
			printf("SELECT OK\n");

			memcpy(capdu,"\x00\xa4\x00\x0c\x02\xe1\x03",7);
			capdulen = 7;
			rapdulen = sizeof(rapdu);
			if(CardTransmit(pnd,capdu,capdulen,rapdu,&rapdulen)<0)
				exit(EXIT_FAILURE);
			if(rapdulen<2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00) {
				capdu[3] = '\x00';
				if(CardTransmit(pnd,capdu,capdulen,rapdu,&rapdulen)<0)
					exit(EXIT_FAILURE);
			}
			printf("CAP CONT SELECTED");







			memcpy(capdu,"\x00\xb0\x00\x00\x0f",5);
			capdulen = 5;
			rapdulen = sizeof(rapdu);
			if(CardTransmit(pnd,capdu,capdulen,rapdu,&rapdulen)<0) {
				exit(EXIT_FAILURE);
			if(rapdulen<2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00) 
				exit(EXIT_FAILURE);
			printf("Cap container hearder :\n");
			size_t szPos;
			for(szPos=0;szPos<rapdulen-2; szPos++) {
				printf("%02x ",rapdu[szPos]);
			}
			printf("\n");
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
	}
	nfc_exit(context);
	exit(EXIT_SUCCESS);


	return 0;

}