

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <time.h>

#include <openssl/bn.h>

#include <openssl/sha.h>

#include <openssl/hmac.h>

#include <openssl/evp.h>

#include <openssl/bio.h>

#include <openssl/buffer.h>

#include <openssl/rsa.h>

#include <openssl/pem.h>

#include "ReadMBMLoader.h"



using namespace std;



unsigned long readBufLong(unsigned char *buffer, unsigned long offset)

{

	return (unsigned long)buffer[offset] + ((unsigned long)buffer[offset+1] << 8) + 

		((unsigned long)buffer[offset+2] << 16) + ((unsigned long)buffer[offset+3] << 24);

}



void swap(unsigned char &a, unsigned char &b) {

	unsigned char t=a;

	a=b;

	b=t;

}



void Key::SetKey(unsigned char *buffer)

{

	ID = readBufLong(buffer, 0x0);

	Type = readBufLong(buffer, 0x4);

	Rights = readBufLong(buffer, 0x8);	

	ModuloLength = readBufLong(buffer, 0xc);	

	EValue = readBufLong(buffer, 0x10);

	if (Modulo) delete [] Modulo;	

	Modulo = new unsigned char [ModuloLength];

	memcpy(Modulo, buffer+0x14, ModuloLength);

	for (int i=0;i<(ModuloLength>>1);i++) swap(Modulo[i],Modulo[ModuloLength-1-i]);	



	if (rsakey) RSA_free(rsakey);	

	rsakey = RSA_new();

	BIGNUM *n = BN_bin2bn(Modulo, ModuloLength, NULL);

	unsigned char buf[4];

	buf[0] = EValue>>24;

	buf[1] = (EValue>>16) & 0xff;

	buf[2] = (EValue>>8) & 0xff;

	buf[3] = EValue & 0xff;

	BIGNUM *e = BN_bin2bn(buf, 4, NULL);

	if (rsakey->n) BN_free(n);

	rsakey->n = n;

	if (rsakey->e) BN_free(e);

	rsakey->e = e;



	SHA1(buffer, ModuloLength+0x14, sha1hash);

}



void Key::PrintKey()

{

	int i;

	fprintf(stdout, "ID=%08x\nType=%08x\nRights=%08x\nModuloLength(in Bits)=%d\nEValue=%d\n",

		(unsigned int) ID, (unsigned int) Type, (unsigned int) Rights,

		(unsigned int) ModuloLength << 3, (unsigned int)EValue);

	for (i=0; i<ModuloLength; i++) fprintf (stdout, "%02x ", (unsigned int)(Modulo[i]));

	fprintf (stdout, "\n");

	fprintf(stdout, "SHA1=");

	for (i=0; i<20; i++) fprintf (stdout, "%02x ", (unsigned int)(sha1hash[i]));

	fprintf (stdout, "\n");

}



int Key::WritePEM(const char *fname)

{

	int i;

	char *fwext = new char [strlen(fname)+10];

	strcpy(fwext, fname);

	strcat(fwext, ".pem");

	FILE *f = fopen(fwext, "w");

	PEM_write_RSA_PUBKEY(f, rsakey);

	fclose(f);

	strcpy(fwext, fname);

	strcat(fwext, ".sha1");

	f = fopen(fwext, "w");

	for (i=0; i<20; i++) fprintf (f, "%02x ", (unsigned int)(sha1hash[i]));

	fprintf (f, "\n");

	fclose(f);

	delete [] fwext;

}



void Fragment::SetFragment(unsigned char *buffer, unsigned char *base)

{

	Offset = readBufLong(buffer, 0x0);

	Length = readBufLong(buffer, 0x4);

	memcpy(sha1hash, buffer + 0x8, 20);



	if (Data) delete [] Data;

	Data = new unsigned char [Length];

	memcpy(Data, base+Offset, Length);

	

	SHA1(base+Offset, Length, sha1calc);	

}



void Fragment::PrintFragment()

{

	int i;

	fprintf(stdout, "Binary Fragment: Offset=%08x Length=%08x\nSha1 TOC =", (unsigned int)Offset, (unsigned int)Length);

	for (i=0; i<20; i++) {fprintf(stdout, "%02x ", sha1hash[i]);}

	fprintf(stdout, "\nSha1 Calc=");

	for (i=0; i<20; i++) {fprintf(stdout, "%02x ", sha1calc[i]);}

	fprintf(stdout, "\n");
	if (!strncmp((const char *)sha1hash, (const char *)sha1calc,20)) {

		fprintf(stdout, "------------------------ FRAGMENT SHA1 VERIFICATION SUCCESSFUL ---------------------------------------\n");

	} else {

		fprintf(stdout, "------------------------ FRAGMENT SHA1 VERIFICATION FAILED -------------------------------------------\n");

	}

}



CertPK::~CertPK() {

	if (Keys) {

		for (int i=0; i<NumberKeys+1; i++) delete Keys[i];

		delete [] Keys;

	}

	if (Signature) delete Signature;

}



void CertPK::SetCertPK(unsigned char *buffer)

{

	int i;



	memcpy(Name, buffer, 8);

	Name[8]=0;



	if (strcmp(Name, "CertPK_")) {

		fprintf(stderr, "ERROR: Invalid Signature, CertPK_ expected, found %s\n", Name);

		return;

	}



	CertVersion = readBufLong(buffer, 0x8);

	CertType = readBufLong(buffer, 0xc);

	MinVerPK = readBufLong(buffer, 0x10);

	MinVerPPA = readBufLong(buffer, 0x14);

	MinVerRD1 = readBufLong(buffer, 0x18);

	MinVerRD2 = readBufLong(buffer, 0x1c);

	MinVerISW = readBufLong(buffer, 0x20);

	MinVerKI = readBufLong(buffer, 0x24);

	MinVerPAU = readBufLong(buffer, 0x28);

	MinVerPAS = readBufLong(buffer, 0x2c);

	WatchdogParam = readBufLong(buffer, 0x30);



	NumberKeys = readBufLong(buffer, 0x148);

	Keys = new Key *[NumberKeys+1];

	for (i=0;i<NumberKeys+1;i++) Keys[i] = new Key();

	Keys[0]->SetKey(buffer+0x34);

	for (i=1;i<NumberKeys+1;i++) Keys[i]->SetKey(buffer+0x14c+(i-1)*0x114); 



	Rights = readBufLong(buffer, 0x7c4);

	MSV = readBufLong(buffer, 0x7c8);

	MSVMask = readBufLong(buffer, 0x7cc);



	SHA1(buffer, 0x848, sha1hash);



	if (Signature) delete Signature;

	Signature = new PKSignature();

	Signature->DecodePKSignature(buffer + 0x848, this);

}



void CertPK::PrintCertPK()

{

	if (!Keys) return;

	int i;

	fprintf(stdout, "Name: %s\n", Name);

	fprintf(stdout, "CertVersion=%08x\nCertType=%08x\nMinVerPK=%08x\nMinVerPPA=%08x\nMinVerRD1=%08x\nMinVerRD2=%08x\nMinVerISW=%08x\nMinVerKI=%08x\nMinVerPAU=%08x\n"

		"MinVerPAS=%08x\nWatchdogParam=%08x\n",

		(unsigned int)CertVersion, (unsigned int)CertType, (unsigned int)MinVerPK, (unsigned int)MinVerPPA, (unsigned int)MinVerRD1, (unsigned int)MinVerRD2, 

		(unsigned int)MinVerISW, (unsigned int)MinVerKI, (unsigned int)MinVerPAU, (unsigned int)MinVerPAS, (unsigned int)WatchdogParam);

	if (Keys[0]) {

		fprintf(stdout, "MasterKey:\n");

		Keys[0]->PrintKey();

	}

	for (i=1;i<NumberKeys+1;i++) {

		if (Keys[i]) {

			fprintf(stdout, "Key%02d:\n", i);

			Keys[i]->PrintKey();

		}

	}



	fprintf(stdout, "Rights=%08x\nMSV=%08x\nMSVMask=%08x\n", (unsigned int) Rights, (unsigned int) MSV, (unsigned int) MSVMask);



	if (Signature) Signature->PrintPKSignature();

	fprintf(stdout, "SHA1 Hash=");

	for (i=0;i<20;i++) fprintf(stdout, "%02x ", (unsigned int)(sha1hash[i]));

	fprintf(stdout, "\n");


	if (!strncmp((const char *)sha1hash, (const char *)Signature->Digest,20)) {

		fprintf(stdout, "----------------------------- PK SHA1 VERIFICATION SUCCESSFUL ---------------------------------------\n");

	} else {

		fprintf(stdout, "----------------------------- PK SHA1 VERIFICATION FAILED -------------------------------------------\n");

	}

}



int CertPK::WritePEM(const char *fname)

{

	char str[256];

	for (int i=0; i<NumberKeys+1;i++) {

		if (Keys[i]) {

			sprintf(str, "%s_%02d", fname, i);

			Keys[i]->WritePEM(str);

		}

	}

}



int PKSignature::DecodePKSignature(unsigned char *buffer, CertPK *PKeys) 

{

	int i;

	int dgst_size;

	unsigned char result[512];



	if (SignerInfo) delete [] SignerInfo;

	SignerInfo = new unsigned char [0x10];

	memcpy(SignerInfo, buffer,0x10);

	SignatureInfo = readBufLong(buffer, 0x10);	

	KeyID = readBufLong(buffer, 0x14);



	int KeyNumber = PKeys->FindKey(KeyID);

	if (KeyNumber == -1) return -1;

	memset(result, 0, PKeys->Keys[KeyNumber]->ModuloLength);

	dgst_size = RSA_public_decrypt(PKeys->Keys[KeyNumber]->ModuloLength, buffer + 0x18, result, 

		PKeys->Keys[KeyNumber]->rsakey, RSA_NO_PADDING);

/*	for (i=0; i<dgst_size; i++) fprintf(stdout, "%02x ", result[i]);

	fprintf(stdout, "\n");*/

	unsigned char *resptr = result;

	if (*resptr != 0) return -1;

	resptr++;

	if (*resptr != 1) return -1;

	resptr++;

	unsigned long count=0;

	while (*resptr == 0xff) {

		count++;

		resptr++;

	}

	if (count < 8) return -1;

	if (*resptr != 0) return -1;

	resptr++;

	const char sha1ident[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,

		0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

	if (strncmp((const char *)resptr, sha1ident, 15)) return -1;

	resptr+=15;

	DigestSize = dgst_size - count - 3 - 15;

	if (Digest) delete [] Digest;

	Digest = new unsigned char [DigestSize];

	memcpy(Digest, resptr, DigestSize);

	return 0;

}



void PKSignature::PrintPKSignature()

{

	int i;

	fprintf(stdout, "SignerInfo=");

	for (i=0;i<0x10;i++) fprintf(stdout, "%02x ", (unsigned int)(SignerInfo[i]));

	fprintf(stdout, "\n");

	time_t signtime = SignerInfo[0] + (SignerInfo[1] << 8) + (SignerInfo[2] << 16) + (SignerInfo[3] << 24);

	struct tm *ts = localtime(&signtime);

	char buf[80];

	strftime(buf, sizeof(buf), "%a %d.%m.%Y %H:%M:%S %Z", ts);

	fprintf(stdout, "Matching UNIX timestamp: %s\n", buf);

	fprintf(stdout, "SignatureInfo=%08x\n", (unsigned int)(SignatureInfo));	

	fprintf(stdout, "Signed with KeyID=%d\n", (unsigned int)KeyID);

	if (Digest) {

		fprintf(stdout, "SHA1 Digest=");

		for (i=0;i<DigestSize;i++) fprintf(stdout, "%02x ", (unsigned int)(Digest[i]));

		fprintf(stdout, "\n");

	}

}



CertPPA::~CertPPA()

{

	if (Signature) delete Signature;

}



void CertPPA::SetCertPPA(unsigned char *buffer, CertPK *PKeys)

{

	memcpy(Name, buffer, 8);

	Name[8]=0;



	if (strcmp(Name, "CertPPA")) {

		fprintf(stderr, "ERROR: Invalid Signature, CertPPA expected, found %s\n", Name);

		return;

	}



	CertVersion = readBufLong(buffer, 0x8);

	CertType = readBufLong(buffer, 0xc);

	MinVerSRC = readBufLong(buffer, 0x10);

	MinVerPK = readBufLong(buffer, 0x14);

	MinVerPPA = readBufLong(buffer, 0x18);

	MinVerRD1 = readBufLong(buffer, 0x1c);

	MinVerRD2 = readBufLong(buffer, 0x20);

	MinVerISW = readBufLong(buffer, 0x24);



	Image.SetFragment(buffer+0x28, buffer);



	SHA1(buffer, 0xc4, sha1hash);



	if (Signature) delete Signature;

	Signature = new PKSignature();

	Signature->DecodePKSignature(buffer + 0xc4, PKeys);

}



void CertPPA::PrintCertPPA()

{

	int i;

	fprintf(stdout, "Name: %s\n", Name);



	fprintf(stdout, "CertVersion=%08x\nCertType=%08x\nMinVerSRC=%08x\nMinVerPK=%08x\nMinVerPPA=%08x\nMinVerRD1=%08x\nMinVerRD2=%08x\nMinVerISW=%08x\n",

		(unsigned int)CertVersion, (unsigned int)CertType, (unsigned int)MinVerSRC, (unsigned int)MinVerPK, (unsigned int)MinVerPPA, 

		(unsigned int)MinVerRD1, (unsigned int)MinVerRD2, (unsigned int)MinVerISW);



	Image.PrintFragment();



	if (Signature) Signature->PrintPKSignature();	

	fprintf(stdout, "SHA1 Hash=");

	for (i=0;i<20;i++) fprintf(stdout, "%02x ", (unsigned int)(sha1hash[i]));

	fprintf(stdout, "\n");



	if (!strncmp((const char *)sha1hash, (const char *)Signature->Digest,20)) {

		fprintf(stdout, "----------------------------- PPA SHA1 VERIFICATION SUCCESSFUL ---------------------------------------\n");

	} else {

		fprintf(stdout, "----------------------------- PPA SHA1 VERIFICATION FAILED -------------------------------------------\n");

	}

}	



void CertPPA::WritePPA(const char *fname)

{

	char str[256];

	sprintf(str, "%s.bin", fname);

	FILE *f = fopen(str, "w");

	if (f) {

		fwrite(Image.Data, 1, Image.Length, f);

	}

	fclose(f);

}



CertISW::~CertISW()

{

	int i;

	if (Images) {

		for (i=0; i<ISWNumberImages; i++) delete Images[i];

		delete [] Images;

	}



	if (Signature) delete Signature;

}



void CertISW::SetCertISW(unsigned char *buffer, CertPK *PKeys)

{

	int i;

	memcpy(Name, buffer, 8);

	Name[8]=0;



	if (strcmp(Name, "CertISW")) {

		fprintf(stderr, "ERROR: Invalid Signature, CertISW expected, found %s\n", Name);

		return;

	}



	CertVersion = readBufLong(buffer, 0x8);

	CertType = readBufLong(buffer, 0xc);

	MinVerSRC = readBufLong(buffer, 0x10);

	MinVerPK = readBufLong(buffer, 0x14);

	MinVerPPA = readBufLong(buffer, 0x18);

	MinVerRD1 = readBufLong(buffer, 0x1c);

	MinVerRD2 = readBufLong(buffer, 0x20);

	MinVerISW = readBufLong(buffer, 0x24);

	Watchdog = readBufLong(buffer, 0x28);

	UseDMA = readBufLong(buffer, 0x2c);

	

	ISWNumberImages = readBufLong(buffer, 0x30);

	Images = new Fragment *[ISWNumberImages];

	for (i=0; i<ISWNumberImages; i++) {

		Images[i] = new Fragment();

		Images[i]->SetFragment(buffer+0x34+0x1c*i, buffer);

	}

	

	Magic1 = readBufLong(buffer, 0xa4);

	if (Magic1 != 0x16793a22) fprintf(stderr,"INFO: Magic byte field has value %08x, in all observed cases this field has the value 0x16793a22\n", (unsigned int)Magic1);

	RegBitfield = readBufLong(buffer, 0xa8);

	for (i=0; i<32; i++) {

		RegAddress[i] = readBufLong(buffer, 0xac + 0x8 * i); 

		RegValue[i] = readBufLong(buffer, 0xb0 + 0x8 * i); 

	}

	RegType1 = readBufLong(buffer, 0x1ac);

	RegType2 = readBufLong(buffer, 0x1b0);



	OffsetImage = readBufLong(buffer, 0x1b4);



	SHA1(buffer, 0x238, sha1hash);



	if (Signature) delete Signature;

	Signature = new PKSignature();

	Signature->DecodePKSignature(buffer + 0x238, PKeys);

}



void CertISW::PrintCertISW()

{

	int i;

	fprintf(stdout, "Name: %s\n", Name);



	fprintf(stdout, "CertVersion=%08x\nCertType=%08x\nMinVerSRC=%08x\nMinVerPK=%08x\nMinVerPPA=%08x\nMinVerRD1=%08x\nMinVerRD2=%08x\nMinVerISW=%08x\n",

		(unsigned int)CertVersion, (unsigned int)CertType, (unsigned int)MinVerSRC, (unsigned int)MinVerPK, (unsigned int)MinVerPPA, 

		(unsigned int)MinVerRD1, (unsigned int)MinVerRD2, (unsigned int)MinVerISW);

	fprintf(stdout, "Watchdog=%08x\nUseDMA=%s\n", (unsigned int)Watchdog, UseDMA ? "on" : "off");



	for (i=0; i<32; i++) {

		if (RegBitfield & (1<<i)) {

			fprintf (stdout, "SpeedUp Reg %d enabled : Address=%08x Value=%08x ", i, (unsigned int)RegAddress[i], (unsigned int)RegValue[i]);

			int RegType = ((RegType1 >> i) & 1) + (((RegType2 >> i) & 1) << 1);

			switch (RegType) {

				case 0: fprintf(stdout, "Write\n");

						break;

				case 1: fprintf(stdout, "Poll Reset\n");

						break;

				case 2: fprintf(stdout, "Poll Set\n");

						break;

				case 3: fprintf(stdout, "Poll Value\n");

						break;

			}

		}

	}



	fprintf(stdout, "Offset Value=%08x (in CSST=%08x)\n", (unsigned int)OffsetImage, (unsigned int)(OffsetImage-0x350));



	fprintf(stdout, "Number of Binary Images(Splits)=%d\n", (unsigned int)ISWNumberImages);

	if (Images) for (i=0; i<ISWNumberImages; i++) Images[i]->PrintFragment();



	if (Signature) Signature->PrintPKSignature();
	fprintf(stdout, "SHA1 Hash=");

	for (i=0;i<20;i++) fprintf(stdout, "%02x ", (unsigned int)(sha1hash[i]));

	fprintf(stdout, "\n");



	if (!strncmp((const char *)sha1hash, (const char *)Signature->Digest,20)) {

		fprintf(stdout, "----------------------------- ISW SHA1 VERIFICATION SUCCESSFUL ---------------------------------------\n");

	} else {

		fprintf(stdout, "----------------------------- ISW SHA1 VERIFICATION FAILED -------------------------------------------\n");

	}	

}	



void CertISW::WriteISW(const char *fname)

{

	int i;

	char str[256];

	for (i=0; i<ISWNumberImages; i++) {

		sprintf(str, "%s_%d.bin", fname,i);

		FILE *f = fopen(str, "w");

		if (f) {

			fwrite(Images[i]->Data, 1, Images[i]->Length, f);

		}

		fclose(f);

	}

}



void DirEntry::SetDirEntry(unsigned char *buffer)

{

	Offset = readBufLong(buffer, 0x0);	

	Size = readBufLong(buffer, 0x4);	

	Unknown1 = readBufLong(buffer, 0x8);	

	Unknown2 = readBufLong(buffer, 0xc);	

	LoadAddress = readBufLong(buffer, 0x10);	

	memcpy(Name, buffer + 0x14, 12);

}



void DirEntry::PrintDirEntry()

{

	fprintf (stdout, "Directory Entry: Name=%s Offset=%08x Size=%08x LoadAddress=%08x Unknown1=%08x Unknown2=%08x\n",

		Name, (unsigned int)Offset, (unsigned int)Size, (unsigned int)LoadAddress, 

		(unsigned int)Unknown1, (unsigned int)Unknown2);

}



void Directory::SetDirectory(unsigned char *buffer, unsigned long nOffset)

{

	Offset = nOffset;

	buffer+=Offset;



	char endmarker[32];

	memset(endmarker, 0xff, 32);

	while(strncmp((const char *)buffer, endmarker, 32)) {

		DirEntry *newEntry = new DirEntry();

		newEntry->SetDirEntry(buffer);

		EntryList.push_back(newEntry);

		buffer += 0x20;

	}

}



DirEntry *Directory::FindDirEntry(const char *entryName)

{

	for (vector<DirEntry *>::iterator iter=EntryList.begin(); iter!=EntryList.end(); iter++) {

		if (!strncmp((*iter)->Name, entryName, 12)) return *iter;

	}

	return NULL;

}



void Directory::PrintDirectory()

{

	fprintf (stdout, "Directory contains %d entries.\n", (int)EntryList.size());

	for (vector<DirEntry *>::iterator iter=EntryList.begin(); iter!=EntryList.end(); iter++) {

		(*iter)->PrintDirEntry();

	}

}



void MTD0::SetMTD0(unsigned char *buffer)

{

	if (mtdSettingsDir) delete mtdSettingsDir;

	mtdSettingsDir = new Directory();

	mtdSettingsDir->SetDirectory(buffer, 0x0);



	if (mtdCertDir) delete mtdCertDir;

	mtdCertDir = new Directory();

	mtdCertDir->SetDirectory(buffer, 0x200);



	DirEntry *keys = mtdCertDir->FindDirEntry("KEYS");

	if (keys) {

		if (mtdCertPK) delete mtdCertPK;

		mtdCertPK = new CertPK();

		mtdCertPK->SetCertPK(buffer+mtdCertDir->Offset+keys->Offset);

	}



	DirEntry *ppa = mtdCertDir->FindDirEntry("PRIMAPP");

	if (ppa) {

		if (mtdCertPPA) delete mtdCertPPA;

		mtdCertPPA = new CertPPA();

		mtdCertPPA->SetCertPPA(buffer+mtdCertDir->Offset+ppa->Offset, mtdCertPK);

	}



	DirEntry *isw = mtdCertDir->FindDirEntry("X-LOADER");

	if (isw) {

		if (mtdCertISW) delete mtdCertISW;

		mtdCertISW = new CertISW();

		mtdCertISW->SetCertISW(buffer+mtdCertDir->Offset+isw->Offset, mtdCertPK);

	}

}



void MTD0::PrintMTD0()

{

	mtdSettingsDir->PrintDirectory();

	mtdCertDir->PrintDirectory();

	mtdCertPK->PrintCertPK();	

	mtdCertPPA->PrintCertPPA();

	mtdCertISW->PrintCertISW();

}



int main (int argc, char **argv)

{

	unsigned char *buffer = NULL;

	FILE *f = fopen(argv[1], "rb");

	if (f) {

		int pos;

		int end;



		pos = ftell(f);

		fseek(f, 0, SEEK_END);

		end = ftell (f);

		fseek(f, pos, SEEK_SET);



		buffer = new unsigned char[end];

		pos = fread(buffer,1,end,f);

		if (pos!=end) return -1; 

	}

	fclose (f);



	MTD0 *mtd = new MTD0();

	mtd->SetMTD0(buffer);

	mtd->PrintMTD0();

	mtd->mtdCertPK->WritePEM("milekeys");

	mtd->mtdCertPPA->WritePPA("mileppa");

	mtd->mtdCertISW->WriteISW("mileisw");

	delete mtd;



	return 0;

}