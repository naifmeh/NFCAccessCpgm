#define RANK_COL 5
#define UID_COL 1
#define NAME_COL 2
#define LNAME_COL 3;

static const char* TableName = "authUsers";

size_t static write_callback_func(void *buffer,
                        size_t size,
                        size_t nmemb,
                        void *userp);

/*
* Function used for verbose mode to print valuable infos
*/
static void print_usage(const char *argv[]) {
	printf("Utilisation: %s [OPTIONS]\n",argv[0]);
	printf("Options:\n");
	printf("\t-h\tPrint this help message.\n");
    printf("\t-v\tSet verbose display.\n");
    printf("\t-i\tAllow intrusive scan.\n");
}

/*
* Helper function that prints a byte array (pbData)
* size of array should be provided for faster processing.
*/
void print_hex(const uint8_t *pbtData, const size_t szLen)
{
  size_t  szPos;

  for (szPos = 0; szPos < szLen; szPos++) {
    printf("%02x  ", pbtData[szPos]);
  }
  printf("\n");

}
/*
* Convert a char array into lowercase using the String library
*/
char* lowercase(char* str) {
	int i=0;
	char* str1 = strdup(str);

	for(i=0;i<strlen(str);i++) {
		str1[i] = tolower(str1[i]);

	}
	return str1;

}

/*
* Convert a byte array into a string. Helper for handling the
* scanned uid.
* Size of array should be provided.
*/
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

/*
* Helper method that uses the libnfc function to send and read
* low level APDU commands.
* NFC reader should be able to act as a transmitter.
*/
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

/*
* Function executing a HTTP GET request using libcurl.
* Response is also handled and access is granted using the wiringPi library.
* Takes an url as a parameter.
* Return the HTTP status.
*/
long do_web_request(char *url) {
	CURL *curl_handle = NULL;
	char *response = NULL;

	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle,CURLOPT_URL,url);
	curl_easy_setopt(curl_handle,CURLOPT_HTTPGET,1);

	curl_easy_setopt(curl_handle,CURLOPT_FOLLOWLOCATION,1);
	curl_easy_setopt(curl_handle,CURLOPT_VERBOSE,1);


	long http_code = 0;


	curl_easy_perform(curl_handle);
	curl_easy_getinfo (curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code >= 200 && http_code < 300) {
		digitalWrite(0,0);
		delay(50);
		digitalWrite(0,1);
		printf("\n*****ACCESS GRANTED******\n");
	} else printf("\n*/!\\/!\\/!\\**ACCESS REFUSED**/!\\/!\\/!\\");
	curl_easy_cleanup(curl_handle);

	return http_code;

}
size_t static write_callback_func(void *buffer,
                        size_t size,
                        size_t nmemb,
                        void *userp)
{
    char **response_ptr =  (char**)userp;

    /* assuming the response is a string */
    *response_ptr = strndup(buffer, (size_t)(size *nmemb));

}
