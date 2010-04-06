/*

 Sample how to integrate VB UI for IDA plugin
 http://sandsprite.com/CodeStuff/VB_Plugin_for_Olly.html

'Author: David Zimmer <dzzie@yahoo.com> - Copyright 2004
'Site:   http://sandsprite.com
'
'License:
'
'         This program is free software; you can redistribute it and/or modify it
'         under the terms of the GNU General Public License as published by the Free
'         Software Foundation; either version 2 of the License, or (at your option)
'         any later version.
'
'         This program is distributed in the hope that it will be useful, but WITHOUT
'         ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
'         FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
'         more details.
'
'         You should have received a copy of the GNU General Public License along with
'         this program; if not, write to the Free Software Foundation, Inc., 59 Temple
'         Place, Suite 330, Boston, MA 02111-1307 USA


*/

#include <windows.h>  //define this before other headers or get errors 
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <frame.hpp>
#include <dbg.hpp>
#include <area.hpp>



IDispatch        *IDisp;

int StartPlugin(void);

//if no use windows.h you can declare API fx manually like
//extern "C" int GetProcAddress(int h, char* fxName);
//extern "C" int GetModuleHandle(char* modName);


//Initialize.called once. PLUGIN_OK = unload+recall, PLUGIN_KEEP = keep in mem
int idaapi init(void)
{
  if ( inf.filetype == f_ELF ) return PLUGIN_SKIP;

  /*..init stuff here..*/
  
  return PLUGIN_KEEP;
}

//      Terminate.
void idaapi term(void)
{
	try{
		if(IDisp){
			IDisp->Release();
			CoUninitialize();
			IDisp = NULL;
		}
	}
	catch(...){};
	
}

void idaapi run(int arg)
{
 
  StartPlugin();

}

char comment[] = "idacompare";
char help[] ="idacompare";
char wanted_name[] = "IDA Compare";
char wanted_hotkey[] = "Alt-0";

//Plugin Descriptor Block
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin (status line or hint)
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};





int StartPlugin(){

    //Create an instance of our VB COM object, and execute
	//one of its methods so that it will load up and show a UI
	//for us, then it uses our other exports to access olly plugin API
	//methods

	CLSID      clsid;
	HRESULT	   hr;
    LPOLESTR   p = OLESTR("IDACompare.CPlugin");

    hr = CoInitialize(NULL);

	 hr = CLSIDFromProgID( p , &clsid);
	 if( hr != S_OK  ){
		 MessageBox(0,"Failed to get Clsid from string\n","",0);
		 return 0;
	 }

	 // create an instance and get IDispatch pointer
	 hr =  CoCreateInstance( clsid,
							 NULL,
							 CLSCTX_INPROC_SERVER,
							 IID_IDispatch  ,
							 (void**) &IDisp
						   );

	 if ( hr != S_OK )
	 {
	   MessageBox(0,"CoCreate failed","",0);
	   return 0;
	 }

	 OLECHAR *sMethodName = OLESTR("DoPluginAction");
	 DISPID  dispid; // long integer containing the dispatch ID

	 // Get the Dispatch ID for the method name
	 hr=IDisp->GetIDsOfNames(IID_NULL,&sMethodName,1,LOCALE_USER_DEFAULT,&dispid);
	 if( FAILED(hr) ){
	    MessageBox(0,"GetIDS failed","",0);
		return 0;
	 }

	 DISPPARAMS dispparams;
	 VARIANTARG vararg[1]; //function takes one argument
	 VARIANT    retVal;

	 VariantInit(&vararg[0]);
	 dispparams.rgvarg = &vararg[0];
	 dispparams.cArgs = 0;  // num of args function takes
	 dispparams.cNamedArgs = 0;

	 // and invoke the method
	 hr=IDisp->Invoke( dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dispparams, &retVal, NULL, NULL);

	 return 0;
}





//Export API for the VB app to call and access IDA API data
//_________________________________________________________________
void __stdcall Jump      (int addr)  { jumpto(addr);           }
void __stdcall Refresh   (void)      { refresh_idaview();      }
int  __stdcall ScreenEA  (void)      { return get_screen_ea(); }
int  __stdcall NumFuncs  (void)      { return get_func_qty();  }
void __stdcall RemvName  (int addr)  { del_global_name(addr);  }
void __stdcall Setname(int addr, const char* name){ set_name(addr, name); }
//void __stdcall AddComment(char *cmt, char color){ generate_big_comment(cmt, color);}
void __stdcall AddProgramComment(char *cmt){ add_pgm_cmt(cmt); }
void __stdcall AddCodeXRef(int start, int end){ add_cref(start, end, cref_t(fl_F | XREF_USER) );}
void __stdcall DelCodeXRef(int start, int end){ del_cref(start, end, 1 );}
void __stdcall AddDataXRef(int start, int end){ add_dref(start, end, dref_t(dr_O | XREF_USER) );}
void __stdcall DelDataXRef(int start, int end){ del_dref(start, end );}
void __stdcall MessageUI(char *m){ msg(m);}
void __stdcall PatchByte(int addr, char val){ patch_byte(addr, val); }
void __stdcall PatchWord(int addr, int val){  patch_word(addr, val); }
void __stdcall DelFunc(int addr){ del_func(addr); }
int  __stdcall FuncIndex(int addr){ return get_func_num(addr); }
void __stdcall SelBounds( ulong* selStart, ulong* selEnd){ read_selection(selStart, selEnd);}
void __stdcall FuncName(int addr, char *buf, size_t bufsize){ get_func_name(addr, buf, bufsize);}
int  __stdcall GetBytes(int offset, void *buf, int length){ return get_many_bytes(offset, buf, length);}
void __stdcall Undefine(int offset){ autoMark(offset, AU_UNK); }
char __stdcall OriginalByte(int offset){ return get_original_byte(offset); }

void __stdcall SetComment(int offset, char* comm){set_cmt(offset,comm,false);}

void __stdcall GetComment(int offset, char* buf){ 
	int cmtc = get_cmt(offset,false, buf, 800);
/*
	if(tmp){
		//MessageBox(0,tmp,"",0);
		qstrncpy(buf,tmp, 800);
	}
*/
 
}

int __stdcall ProcessState(void){ return get_process_state(); }

int __stdcall FilePath(char *buf){ 
	int retlen=0;
	char *str;

	get_input_file_path(buf, MAX_PATH);
//	qstrncpy(buf,str,MAX_PATH);
	return strlen(buf);
}

int __stdcall RootFileName(char *buf){ 
	int retlen=0;
	char *str;

	get_root_filename(buf, MAX_PATH);
	//qstrncpy(buf,str,MAX_PATH);
	return strlen(buf);
}

void __stdcall HideEA(int offset){	set_visible_item(offset, false); }
void __stdcall ShowEA(int offset){	set_visible_item(offset, true); }

/*
int __stdcall NextAddr(int offset){
   areacb_t a;
   return a.get_next_area(offset);
}

int __stdcall PrevAddr(int offset){
	areacb_t a;
    return a.get_prev_area(offset); 
}
*/


//not working?
//void __stdcall AnalyzeArea(int startat, int endat){ analyse_area(startat, endat);}


//not workign to get labels
void __stdcall GetName(int offset, char* buf, int bufsize){
	get_true_name( BADADDR, offset, buf, bufsize );
}

//not workign to make code and analyze
void __stdcall MakeCode(int offset){
	 
	 /*autoMark(offset, AU_CODE); //not compliant with 4.8 ida sdk
	 analyse_area(offset, (offset+1) );
	 */
}


int __stdcall FunctionStart(int n){
	func_t *clsFx = getn_func(n);
	return clsFx->startEA;
}

int __stdcall FunctionEnd(int n){
	func_t *clsFx = getn_func(n);
	return clsFx->endEA;
}

int __stdcall FuncArgSize(int index){
		func_t *clsFx = getn_func(index);
		return clsFx->argsize ;
}

int __stdcall FuncColor(int index){
		func_t *clsFx = getn_func(index);
		return clsFx->color  ;
}

int __stdcall GetAsm(int addr, char* buf, int bufLen){

    flags_t flags;                                                       
    int sLen=0;

    flags = getFlags(addr);                        
    if(isCode(flags)) {                            
        generate_disasm_line(addr, buf, bufLen, GENDSM_MULTI_LINE );
        sLen = tag_remove(buf, buf, bufLen);  
    }

	return sLen;

}

