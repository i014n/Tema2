#include "so_stdio.h"
#include<stdio.h>

#define FILE_NULL -1

#define READ_OPERATION 100
#define WRITE_OPERATION 101
#pragma warning (disable:4996)
//static int CheckFileValability(SO_FILE* stream) {
//	if (stream == NULL)
//		return FILE_NULL;
//}

static int Last_Operation = 0;

static int ReturnModeAcces(const char *mode) {

	DWORD rMode = ERROR;
	if(strncmp("r", mode, sizeof(mode)) == 0)
		rMode = GENERIC_READ;
	if (strncmp("r+", mode, sizeof(mode)) == 0)
		rMode = (GENERIC_READ|GENERIC_WRITE);
	if (strncmp("w", mode, sizeof(mode)) == 0)
		rMode = GENERIC_WRITE;
	if (strncmp("w+", mode, sizeof(mode)) == 0)
		rMode = (GENERIC_READ|GENERIC_WRITE);
	if (strncmp("a", mode, sizeof(mode)) == 0)
		rMode = (GENERIC_READ | GENERIC_WRITE);
	if (strncmp("a+", mode, sizeof(mode)) == 0)
		rMode = (GENERIC_READ | GENERIC_WRITE);
	return rMode;

}

static int soCreationDisposition(const char *mode) {

	DWORD rAccesMode = ERROR;
	if (strncmp("r", mode, sizeof(mode))==0)
		rAccesMode = OPEN_EXISTING;
	if (strncmp("r+", mode, sizeof(mode)) == 0)
		rAccesMode = OPEN_EXISTING;
	if (strncmp("w", mode, sizeof(mode)) == 0)
		rAccesMode = OPEN_ALWAYS;
	if (strncmp("w+", mode, sizeof(mode)) == 0)
		rAccesMode = OPEN_ALWAYS;
	if (strncmp("a", mode, sizeof(mode)) == 0)
		rAccesMode = OPEN_ALWAYS;
	if (strncmp("a+", mode, sizeof(mode)) == 0)
		rAccesMode = OPEN_ALWAYS;
	return rAccesMode;
}

static void SeekPosition(SO_FILE *stream, const char *mode) {
	
	BOOL bRet;
	if (strncmp("a", mode, sizeof(mode)) == 0 ||
		strncmp("a+", mode, sizeof(mode)) == 0)
		bRet = SetFilePointer(stream->so_handle,
			0,
			NULL,
			FILE_END
		);
}

static void CheckLastOperation(SO_FILE *stream, int CurentOperation) {

	DWORD bytesWriten;
	BOOL bRet;
	if (CurentOperation != READ_OPERATION 
		&& Last_Operation == WRITE_OPERATION) {
		bRet = WriteFile(stream->so_handle,
			stream->buffer,
			stream->bufSize,
			&bytesWriten,
			NULL);
		if (bRet > 0) {

			stream->bufSize = 0;
			memset(stream->buffer, 0, sizeof(stream->buffer));
		}
		
	}
	if (CurentOperation != WRITE_OPERATION
		&& Last_Operation == READ_OPERATION)
	{
		stream->bufSize = 0;
		memset(stream->buffer, 0, sizeof(stream->buffer));
	}
}

static void CheckLastOperationV2(SO_FILE* stream) {
	BOOL bRet;
	DWORD bytesWriten;
	if (Last_Operation == READ_OPERATION) {
		stream->bufSize = 0;
		memset(stream->buffer, 0, sizeof(stream->buffer));
	}
	if (Last_Operation == WRITE_OPERATION) {
		bRet = WriteFile(stream->so_handle,
			stream->buffer,
			stream->bufSize,
			&bytesWriten,
			NULL);
		if (bRet > 0) {

			stream->bufSize = 0;
			memset(stream->buffer, 0, sizeof(stream->buffer));
		}
	}
}

static char* ReadElement(SO_FILE *stream, size_t nmemb) {
	char* rElement =(char *)malloc(nmemb * sizeof(char) + 1);

	if (rElement != NULL) {
		memset(rElement, 0, nmemb * sizeof(char) + 1);

		if (stream->bufSize >=  nmemb)
			stream->bufSize -= nmemb;
		else nmemb = stream->bufSize;

		strncpy(rElement, stream->buffer, nmemb);
		strcpy(stream->buffer, stream->buffer + nmemb);
	}
	rElement[strlen(rElement)] = '\0';
	return rElement;
}


 SO_FILE* so_fopen(const char* pathname, const char* mode) {
	 SO_FILE* retFile = (SO_FILE*)malloc(sizeof(_so_file));
	 if (retFile != NULL) {
		 retFile->so_handle = CreateFile(pathname,
			 ReturnModeAcces(mode),
			 0,
			 NULL,
			 soCreationDisposition(mode),
			 FILE_ATTRIBUTE_NORMAL,
			 NULL
		 );
		 memset(retFile->buffer, 0, sizeof(retFile->buffer));
		 retFile->bufSize = 0;
		 //retFile->buffer = (char*)malloc(SIZE_BUFFER * sizeof(char));
		 SeekPosition(retFile,mode);
	 } 


	return retFile;
}

int so_fclose(SO_FILE *stream) {
	 
	 if (stream != NULL) {
		 // 
		 free(stream);
		 return 0;
	 }
	 return SO_EOF;
 }

HANDLE so_fileno(SO_FILE *stream) {
	  if (stream != NULL)
		  return stream->so_handle;
	  else 
		return INVALID_HANDLE_VALUE;
 }

int so_fflush(SO_FILE* stream)
  {
	  BOOL bRet;
	  DWORD bytesWriten;
	  int rCode = 0;

	  if (Last_Operation == WRITE_OPERATION) {
		 
		 
			  bRet = WriteFile(stream->so_handle,
				  stream->buffer,
				  stream->bufSize,
				  &bytesWriten,
				  NULL);
			  if (bRet > 0) {

				  stream->bufSize = 0;
				  memset(stream->buffer, 0, sizeof(stream->buffer));

			  }
			  else rCode = SO_EOF;
			  
		 
	 }
	  return rCode;
  }

int so_fseek(SO_FILE* stream, long offset, int whence)
  {
	  CheckLastOperationV2(stream);
	  BOOL bRet = SetFilePointer(stream->so_handle,
		  offset,
		  NULL,
		  whence);
	  
	  return bRet;
  }

long so_ftell(SO_FILE* stream)
  {
	  BOOL bRet = SetFilePointer(stream->so_handle,
		  0,
		  NULL,
		  SEEK_CUR);
 	  return bRet;
	  
  }

size_t so_fread(void* ptr, size_t size, size_t nmemb, SO_FILE* stream)
  {
	 DWORD bytesRead;
	 BOOL bRet=0;
	 size_t count = 0;
	 char * my_ptr = (char *)ptr;
	 for (int i = 0; i < nmemb; i++) {
		 int offset = i * size;
		 if (stream->bufSize == 0) {
			bRet = ReadFile(stream->so_handle,
				 stream->buffer,
				 BUFFER_SIZE,
				 &bytesRead,
				 NULL);
			 stream->bufSize += bytesRead;
		 }
		 if (bRet < 0)
			 return 0;
		 
		char* element = ReadElement(stream, size);
		if (strlen(element) >= size)
			count++;
		 memcpy(my_ptr + offset, element, size);
		 if (strlen(element) == 0)
			 i = nmemb;
		 if (element != NULL)
			 free(element);

		 element = NULL;
		 
	 }
	 //my_ptr[size] = '\0';
	 return count;
  }

int so_fgetc(SO_FILE* stream){
	  
	  CheckLastOperation(stream, READ_OPERATION);

	  char rChar = SO_EOF;
	  DWORD bytesRead;
	  BOOL bRet;
	  if (stream->bufSize == 0) {
		  bRet = ReadFile(stream->so_handle,
			  stream->buffer,
			  1,		//1 bytes to read
			  &bytesRead,
			  NULL);
		  stream->bufSize += bytesRead;
	  }
	  if (stream->bufSize > 0) {
		  rChar = stream->buffer[0];
		  Last_Operation = READ_OPERATION;
		  strcpy_s(stream->buffer, sizeof(stream->buffer + 1), stream->buffer + 1);
		  stream->bufSize--;
	  }
		  else
			  rChar = SO_EOF;
	  
	  return rChar;
  }

int so_fputc(int c, SO_FILE* stream)
  {
	  CheckLastOperation(stream, WRITE_OPERATION);

	  DWORD bytesWriten;
	  char rChar = SO_EOF;
	  BOOL bRet;
	  if (stream->bufSize == BUFFER_SIZE - 1) {
		  bRet = WriteFile(stream->so_handle,
			  stream->buffer,
			  stream->bufSize,
			  &bytesWriten,
			  NULL);
		  
	  } else {
		  stream->buffer[stream->bufSize] = c;
		  stream->bufSize++;
		  Last_Operation = WRITE_OPERATION;
	  }
	  
	  if (bRet > 0) {
		  
		  stream->bufSize = 0;
		  memset(stream->buffer, 0, sizeof(stream->buffer));
	  }

	  return rChar;
  }

int so_feof(SO_FILE* stream) {

	int curetPosition = so_ftell(stream);
	if(curetPosition == so_fseek(stream,0,SEEK_END)) {
		so_fseek(stream, curetPosition, SEEK_SET);
		return 0;
	}
	return 1;
  }

int so_ferror(SO_FILE* stream)
{
	if(stream->buffer == INVALID_HANDLE_VALUE) 
		return 1;
	return 0;
}
