// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp aes.cpp -o aes.out -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp aes.cpp -o aes.out -lcryptopp -lpthread

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
#include <string>
using std::string;
using std::cout;
using std::cin;
using std::endl;
using std::find;
using std::cerr;

#include <cstdlib>
using std::exit;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::byte;
using CryptoPP::SimpleKeyingInterface;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StreamTransformation;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/ccm.h>
using CryptoPP::CBC_Mode;
using CryptoPP::CTR_Mode;

#include "assert.h"

#define KEYSIZE 32

string transform_filename(string filename, bool to_cipher)
{
	string temp_name = "";
	string file_extention = "";

	temp_name.clear();
	file_extention.clear();

	size_t extention_pos;
	if(extention_pos = filename.find("."))
	{
		temp_name = filename.substr(0, extention_pos);
		file_extention = filename.substr(extention_pos);
	}
	else 
		temp_name = filename;

	return temp_name + (to_cipher ? "_cipher" : "_recovered") + file_extention;
}

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;
    
	byte key[KEYSIZE];
	prng.GenerateBlock(key, sizeof(key));

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	short mode;
	string encoded, filename;
	cout << "Enter Filename: ";
	cin >> filename;

	cout << "Enter mode CBC<1> or CTR<2>: ";
	cin >> mode;

	bool is_cbc = (mode == 1);
	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		if (is_cbc)
		{
			cout << "CBC Mode Used" << endl;
			CBC_Mode<AES>::Encryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);
			
			//File crypt
			//The StreamTransformationFilter removes
			//padding as required.
			FileSource(filename.c_str(), true, 
				new StreamTransformationFilter(e,
					new FileSink(transform_filename(filename, true).c_str(), true) 
				), true
			);
		}
		else
		{
			cout << "CTR Mode Used" << endl;
			CTR_Mode<AES>::Encryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);
			
			//File crypt
			//The StreamTransformationFilter removes
			//padding as required.
			FileSource(filename.c_str(), true, 
				new StreamTransformationFilter(e,
					new FileSink(transform_filename(filename, true).c_str(), true) 
				), true
			);
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	try
	{
		if (is_cbc)
		{
			CBC_Mode<AES>::Decryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);
			
			//File crypt
			//The StreamTransformationFilter removes
			//padding as required.
			FileSource(transform_filename(filename, true).c_str(), true, 
				new StreamTransformationFilter(e,
					new FileSink(transform_filename(filename, false).c_str(), true) 
				), true
			);
		}
		else
		{
			CTR_Mode<AES>::Decryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);
			
			//File crypt
			//The StreamTransformationFilter removes
			//padding as required.
			FileSource(transform_filename(filename, true).c_str(), true, 
				new StreamTransformationFilter(e,
					new FileSink(transform_filename(filename, false).c_str(), true) 
				), true
			);
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	/*********************************\
	\*********************************/
	return 0;
}

