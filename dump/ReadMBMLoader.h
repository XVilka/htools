#ifndef READMBMLOADER_H
#define READMBMLOADER_H

#include <openssl/rsa.h>
#include <vector>

using namespace std;

class PKSignature;

class Key
{
public: 
	Key() : Modulo(NULL), rsakey(NULL) {}
	~Key() {
		if (Modulo) delete [] Modulo;
		if (rsakey) RSA_free(rsakey);
		rsakey = NULL;
	};

	void SetKey(unsigned char *buffer);
	void PrintKey();
	int WritePEM(const char *fname);

	unsigned long	ID;
	unsigned long	Type;
	unsigned long	Rights;
	unsigned long	ModuloLength;
	unsigned long	EValue;
	unsigned char	*Modulo;

	unsigned char	sha1hash[20];
	RSA 		*rsakey;
};

class Fragment
{
public:
       Fragment() : Data(NULL) {}
       ~Fragment() 
	{
		if (Data) delete [] Data;
	}
       
	unsigned long    Offset;
	unsigned long    Length;
	unsigned char    sha1hash[20];
	
	unsigned char    sha1calc[20];
       
	unsigned char    *Data;
       
	void SetFragment(unsigned char *buffer, unsigned char *base);
	void PrintFragment();
};

class CertPK
{
public:
	CertPK() : Keys(NULL), NumberKeys(0), Signature(NULL) {}
	~CertPK();

	void SetCertPK(unsigned char *buffer);
	void PrintCertPK();
	int WritePEM(const char *fname);
	int FindKey(const unsigned long KeyID) {
		for (int i=0; i<(NumberKeys+1);i++) {
			if (Keys[i]->ID == KeyID) return i;
		}
		return -1;
	}

	char 		Name[9];
	unsigned long	CertVersion;
	unsigned long	CertType;
	unsigned long	MinVerPK;
	unsigned long	MinVerPPA;
	unsigned long	MinVerRD1;
	unsigned long	MinVerRD2;
	unsigned long	MinVerISW;
	unsigned long	MinVerKI;
	unsigned long	MinVerPAU;
	unsigned long	MinVerPAS;
	unsigned long	WatchdogParam;
	
	unsigned long	NumberKeys;
	Key		**Keys;

	unsigned long	Rights;
	unsigned long	MSV;
	unsigned long	MSVMask;

	unsigned char	sha1hash[20];

	PKSignature	*Signature;
};

class CertPPA
{
public:
	CertPPA() : Signature(NULL) {}
	~CertPPA();

	void SetCertPPA(unsigned char *buffer, CertPK *PKeys);
	void PrintCertPPA();
	void WritePPA(const char *fname);

	char 		Name[9];
	unsigned long	CertVersion;
	unsigned long	CertType;
	unsigned long	MinVerSRC;
	unsigned long	MinVerPK;
	unsigned long	MinVerPPA;
	unsigned long	MinVerRD1;
	unsigned long	MinVerRD2;
	unsigned long	MinVerISW;

	Fragment	Image;

	unsigned char	sha1hash[20];

	PKSignature	*Signature;
};

class CertISW
{
public:
	CertISW() : Images(NULL), Signature(NULL) {}
	~CertISW();

	void SetCertISW(unsigned char *buffer, CertPK *PKeys);
	void PrintCertISW();	
	void WriteISW(const char *fname);

	char 		Name[9];
	unsigned long	CertVersion;
	unsigned long	CertType;
	unsigned long	MinVerSRC;
	unsigned long	MinVerPK;
	unsigned long	MinVerPPA;
	unsigned long	MinVerRD1;
	unsigned long	MinVerRD2;
	unsigned long	MinVerISW;
	unsigned long   Watchdog;
	unsigned long   UseDMA;

	unsigned long	Magic1;
 	unsigned long	RegBitfield;
 	unsigned long	RegAddress[32];
 	unsigned long	RegValue[32];
 	unsigned long	RegType1;
 	unsigned long	RegType2;

	unsigned long	OffsetImage;
 
	unsigned long	ISWNumberImages;
	Fragment	**Images;

	unsigned char	sha1hash[20];

	PKSignature	*Signature;
};

class PKSignature
{
public:
	PKSignature() : SignerInfo(NULL), Digest(NULL) {}
	~PKSignature() {
		if (SignerInfo) delete [] SignerInfo;
		if (Digest) delete [] Digest;
	}

	int DecodePKSignature(unsigned char *buffer, CertPK *PKeys);
	void PrintPKSignature();

	unsigned char	*SignerInfo;
	unsigned long	SignatureInfo;
	unsigned long	KeyID;
	unsigned char	*Digest;
	unsigned long	DigestSize;
};

class DirEntry
{
public:
	DirEntry() {}
	~DirEntry() {}
	
	void SetDirEntry(unsigned char *buffer);
	void PrintDirEntry();

	unsigned long	Offset;
	unsigned long	Size;
	unsigned long	Unknown1;
	unsigned long	Unknown2;
	unsigned long	LoadAddress;
	char		Name[12];
};

class Directory
{
public:
	Directory() {}
	~Directory() 
	{
		for (vector<DirEntry *>::iterator iter=EntryList.begin(); iter!=EntryList.end(); iter++) {
			delete *iter;
		}
		EntryList.clear();
	}

	void SetDirectory(unsigned char *buffer, unsigned long nOffset);
	DirEntry *FindDirEntry(const char *entryName);
	void PrintDirectory();

	vector<DirEntry *> EntryList; 
	unsigned long	Offset;
};

class MTD0
{
public:
	MTD0() : mtdSettingsDir(NULL), mtdCertDir(NULL), mtdCertPK(NULL), mtdCertPPA(NULL), mtdCertISW(NULL) {}
	~MTD0() 
	{
		if (mtdSettingsDir) delete mtdSettingsDir;
		if (mtdCertDir) delete mtdCertDir;
		if (mtdCertPK) delete mtdCertPK;
		if (mtdCertPPA) delete mtdCertPPA;
		if (mtdCertISW) delete mtdCertISW;
	}

	void SetMTD0(unsigned char *buffer);
	void PrintMTD0();

	Directory	*mtdSettingsDir;
	Directory	*mtdCertDir;

	//ChSettings 	*mtdChSettings;
	//ChRam		*mtdChRam;
	CertPK		*mtdCertPK;
	CertPPA		*mtdCertPPA;
	CertISW		*mtdCertISW;	
};

#endif // READMBMLOADER_H