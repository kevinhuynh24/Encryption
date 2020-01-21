#include <iostream>
#include <cmath>

#ifndef MARMOSET_TESTING
int main();
#endif

char *encode (char *plaintext, unsigned long key);

char *decode (char *ciphertext, unsigned long key);

char *encode (char *plaintext, unsigned long key) {

	////////////////////////////////////////	////////////////////////////////////////

	// Counts the length of the plaintext
	unsigned int size{0};
	while (plaintext[size] != '\0') {
		++size;
	}

	// Checks if the plaintext can be grouped into 4 characters and makes a new length
	unsigned int length{0};
	if ( size % 4 !=0) {
		int temp{0};
		temp= 4 - (size % 4);
		length= size + temp;
	} else {
		length=size;
	}

	// Turns key from decimal to binary
	unsigned int bin[64]{0};
	for (int temp{0};key > 0; ++temp, key /=2) {
		bin[temp]=key%2;
	}

	// Makes the state array of 256 with 256 characters
	unsigned char arrayS[256]{};
	for (int k{0}; k<256; ++k) {
		arrayS[k]=k;
	}

	////////////////////////////////////////	////////////////////////////////////////

	// Scrambles the state array using a bit from the binary key
	int i{0};
	int j{0};
	unsigned char r{0};
	unsigned char R{0};
	for (unsigned int UWU{0}; UWU<256; ++UWU) {
		int k{0};
		int temp{0};
		k=i%64;
		j=(j + arrayS[i] + bin[k])%256;
		temp=arrayS[i];
		arrayS[i]=arrayS[j];
		arrayS[j]=temp;
		i= (i+1)%256;
	}

	////////////////////////////////////////	////////////////////////////////////////

	// Makes a new plaintext with the added null characters
	unsigned char text[length]{'\0'};
	for (unsigned int k{0}; k < size; ++k) {
		text[k]=plaintext[k];
	}
	////////////////////////////////////////	////////////////////////////////////////

	// Does XOR of the new plaintext with the value of the state array at r
	for (std::size_t OWO{0}; OWO < length; ++OWO) {
		int temp{0};
		i=(i+1)%256;
		j=(j+arrayS[i])%256;
		temp=arrayS[j];
		arrayS[j]=arrayS[i];
		arrayS[i]=temp;
		r=(arrayS[i]+arrayS[j])%256;
		R=arrayS[r];
		text[OWO]^=R;
	}

	////////////////////////////////////////	////////////////////////////////////////

	// Makes a new length that is a a length which is in groups of 5
	unsigned int l=((length/4)*5);

	////////////////////////////////////////	////////////////////////////////////////

	// Makes the encrypted string array
	char *stuffy = new char[l+5]{'\0'};

	// ASCII Armour
	unsigned int looper{0};
	unsigned int loopy{0};
	unsigned int decim{0};

	while ( looper < length/4) {
		unsigned int temp[32]{};
		int shift{24};
		unsigned int power{1};

		// Converts the ASCII value into binary and combines 4 ASCII to binary values into one binary array
		for (int x{0}; x < 4; ++x) {
			for (int y{0}; y < 8; ++y) {
				temp[y+shift]=text[loopy]%2;
				text[loopy]/=2;
			}
			shift-=8;
			++loopy;
		}

		// Converts the combined binary into decimal
		for (int x{0}; x < 32; ++x) {
			decim+=(temp[x] * power);
			power*=2;

		}

		// Converts decimal to Base85
		for (int x{0}; x < 5; ++x) {
			stuffy[(4-x)+(looper*5)]=decim % 85 + 33;
			decim/=85;
		}
		++looper;

	}
	////////////////////////////////////////	////////////////////////////////////////
	return stuffy;
}

char *decode (char *ciphertext, unsigned long key) {

	////////////////////////////////////////	////////////////////////////////////////

	// Counts the length of the ciphertext
	unsigned int l{0};
	while (ciphertext[l]!= '\0') {
		++l;
	}

	////////////////////////////////////////	////////////////////////////////////////

	unsigned int length=(l/5)*4;
	unsigned char text[length]{'\0'};

	////////////////////////////////////////	////////////////////////////////////////

	//Reverse ACSII Armour
	unsigned int decim{0};
	unsigned int looper{0};
	unsigned int loopy{0};

	while (looper < l/5) {
		unsigned int biny[32]{};
		unsigned int shift{24};

		// Converts the ciphertext from Base85 to decimal
		for (int x{0}; x < 5; ++x) {
			decim+=(ciphertext[(x)+(looper*5)]-33)*pow(85,4-x);
		}

		// Converts decimal to binary
		for (int x{0}; x < 32; ++x) {
			biny[x]=decim%2;
			decim/=2;
		}

		// Converts binary to scrambled XOR characters
		for (int x{0}; x < 4; ++x) {
			for (int y{0}; y < 8; ++y) {
				text[loopy]+=biny[y+shift]*pow(2,y);
			}
			shift-=8;
			++loopy;
		}
		++looper;

	}

	////////////////////////////////////////	////////////////////////////////////////

	// Makes the state array with characters from 0 to 255
	unsigned char arrayS[256]{};
	for (int k{0}; k<256; ++k) {
		arrayS[k]=k;
	}

	////////////////////////////////////////	////////////////////////////////////////

	// Converts the key from decimal to binary
	unsigned int bin[64]{0};
	for (int temp{0};key > 0; ++temp, key /=2) {
		bin[temp]=key%2;
	}

	////////////////////////////////////////	////////////////////////////////////////

	// Scrambles the state array using bit k from the binary key
	int i{0};
	int j{0};
	for (unsigned int UWU{0}; UWU<256; ++UWU) {
		int k{0};
		int temp{0};
		k=i%64;
		j=(j + arrayS[i] + bin[k])%256;
		temp=arrayS[i];
		arrayS[i]=arrayS[j];
		arrayS[j]=temp;
		i= (i+1)%256;
	}

	////////////////////////////////////////	////////////////////////////////////////

	// Does XOR of the scrambled XOR with the value of the state array at r which obtains the original text
	unsigned int r{0};
	unsigned char R{0};
	for (std::size_t OWO{0}; OWO < length; ++OWO) {
		int temp{0};
		i= (i+1)%256;
		j= (j+arrayS[i])%256;
		temp=arrayS[i];
		arrayS[i]=arrayS[j];
		arrayS[j]=temp;
		r=(arrayS[i]+arrayS[j])%256;
		R=arrayS[r];
		text[OWO]^=R;
	}

	// Converts the decrypted string array to a pointer array
	char *stuffy = new char[length];
	for (unsigned int k{0}; k < length; ++k) {
		stuffy[k]=text[k];
	}

	////////////////////////////////////////	////////////////////////////////////////

	return stuffy;
}

#ifndef MARMOSET_TESTING
int main() {
	unsigned long key{89963221};
	char ch[]{ "UWU"
	};
	std::cout << "String: " << ch << std::endl;
	std::cout << "Key: " << key << std::endl;
	char *ciphertext {encode(ch,key)};
	std::cout << "Encrypted String: " << ciphertext << std::endl;
	char *plaintext {decode(ciphertext, key)};
	std::cout << "Decrypted String: " << plaintext << std::endl;
	return 0;
}
#endif
