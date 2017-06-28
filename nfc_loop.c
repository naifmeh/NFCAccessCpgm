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

#include "helpers.h"

#define MAX_DEVICES 1
#define MAX_TRIAL 5

static nfc_device *pnd = NULL;




int main(int argc,const char *argv[]) {
	int err_cpt;
	size_t i;
	bool verbose = false;

	const char* uidStr;
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

	nfc_connstring connstrings[MAX_DEVICES];
		size_t szDevicesFound = nfc_list_devices(context,connstrings,MAX_DEVICES);

		if(szDevicesFound == 0) {
			printf("No NFC devices found\n");
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}

		printf("%d NFC found: \n",(int) szDevicesFound);
		char* strinfo= NULL;

		MYSQL mysql; //INIT MYSQL CONTEXT

		init_db(&mysql);

		pnd = nfc_open(context,NULL);
	
	
	//Initialisation NFC 
		

		 //OPEN ONLY AVAILABE NFC DEVICE

		while(nfc_initiator_init(pnd) < 0 && err_cpt < MAX_TRIAL) {
			err_cpt++;
		}
		if(nfc_initiator_init(pnd) <0) {
			nfc_perror(pnd,"nfc_initiator_init");
			exit(EXIT_FAILURE);
		}

		int response = -1;
		int access_flag = 0;
		if(pnd) {
				printf("- %s: \n %s\n",nfc_device_get_name(pnd),nfc_device_get_connstring(pnd));

				const nfc_modulation nmMifare = {
					.nmt = NMT_ISO14443A,
					.nbr = NBR_106
				};
			while(1) {
				access_flag = 0;
				printf("Scanning for targets...\n\n");
				while(nfc_initiator_select_passive_target(pnd,nmMifare,NULL,0,&nt)<=0);
				printf("Target found \n");
				printf("\tUID : ");
				uidStr = lowercase(hexToStr(nt.nti.nai.abtUid,nt.nti.nai.szUidLen));
				print_hex(nt.nti.nai.abtUid,nt.nti.nai.szUidLen);

				response = handleUid(&mysql,uidStr);
			
				switch(response) {
					case 0:

						access_flag = 1;
						break;
					case 3:
						access_flag = 1;
						addAuthUser(&mysql,pnd,&nt,uidStr,nmMifare);
						break;
					case -1:
						access_flag=0;
						break;
					default:
						access_flag=0;
						break;

				}
				if(access_flag == 1) {
					printf("USER IN DATABASE\n\n");
				} else printf("USER NOT IN DATABASE\n\n");
				printf("PLEASE REMOVE CARD \n");
				while(nfc_initiator_target_is_present(pnd,NULL) == 0);
			}
		} else {
			printf("Impossible to open %s device\n\n",connstrings[0]);
			}
	
}