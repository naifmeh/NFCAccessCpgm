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
#include <curl/curl.h>
#include <curl/easy.h>

#include "helpers.h"

#define MAX_DEVICES 1
#define MAX_TRIAL 5

static nfc_device *pnd = NULL;


int main(int argc, const char *argv[]) {
	size_t i;
	bool verbose = false;
	int err_cpt = 0;
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
		ERR("Impossible d\'initialiser libnfc\n");
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
	pnd = nfc_open(context,NULL);

	while(nfc_initiator_init(pnd) < 0 && err_cpt < MAX_TRIAL) {
		err_cpt++;
	}
	if(nfc_initiator_init(pnd) <0) {
		nfc_perror(pnd,"nfc_initiator_init");
		exit(EXIT_FAILURE);
	}

	if(pnd) 
		printf("- %s: \n %s\n",nfc_device_get_name(pnd),nfc_device_get_connstring(pnd));

	const nfc_modulation nmMifare = {
			.nmt = NMT_ISO14443A,
			.nbr = NBR_106
	};

	  printf("Polling for target...\n");
  while (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0);
  printf("Target detected!\n");
		printf("SENDING SELECT APDU AID COMMAND : \n");
while(1) {
		uint8_t capdu[264];
	  size_t capdulen;
	  uint8_t rapdu[264];
	  size_t rapdulen;
	  // Select application
	  memcpy(capdu, "\x00\xA4\x04\x00\x07\xF0\x01\x02\x03\x04\x05\x06", 12);
	  capdulen=12;
	  rapdulen=sizeof(rapdu);
	  if(CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0){
	  	printf("Polling for target...\n");
  		while (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0);
  		printf("Target detected!\n");
	  }
	    
	  if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00) {
	    printf("Polling for target...\n");
  		while (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0);
 		 printf("Target detected!\n");
	}
	  else 
	  	{
	  		uint8_t uid[10];
	  		int j=0;
	  		for(j=0;j<rapdulen-2;j++) {
	  			uid[j] = rapdu[j];
	  		}

	  		char *uidRetrieved = hexToStr(uid,rapdulen-2);
	  		printf("UID : %s\n",uidRetrieved);
	  		char url[500] = "http://127.0.0.1:8080/RestTest/webapi/nfcaccess/get/";
	  		strcat(url,uidRetrieved);

	  		char *content = NULL;
	  		content = do_web_request(url);
	  		printf("\n\n%s\n\n",content);
	  	}

	  printf("Application selected!\n");
	 
	  
	  printf("\n");
}		
	
	nfc_close(pnd);
	nfc_exit(context);
	exit(EXIT_SUCCESS);
	return 0;

}
