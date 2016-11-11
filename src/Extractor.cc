/*
 * steghide 0.5.1 - a steganography program
 * Copyright (C) 1999-2003 Stefan Hetzl <shetzl@chello.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#include <string>
#include <string.h>

#include "BitString.h"
#include "CvrStgFile.h"
#include "EmbData.h"
#include "Extractor.h"
#include "SampleValue.h"
#include "Selector.h"
#include "common.h"
#include "error.h"

//+-------------------------------------------------------------------------+
//| Точка входа                                                             |
//+-------------------------------------------------------------------------+
EmbData* Extractor::extract ()
   {
    VerboseMessage vrs;
//--- пишем о том откуда читаем стегофайл
    if(Args.StgFn.getValue()=="") { vrs.setMessage (_("reading stego file from standard input...")) ;                   }
    else                          { vrs.setMessage (_("reading stego file \"%s\"..."), Args.StgFn.getValue().c_str()) ; }
    vrs.setNewline(false);
    vrs.printMessage();
//--- считываем стегофайл
	Globs.TheCvrStgFile = CvrStgFile::readFile (StegoFileName) ;

	VerboseMessage vd (_(" done")) ;
	vd.printMessage() ;

    VerboseMessage ve (_("extracting data...")) ;
    ve.setNewline (false) ;
    ve.printMessage() ;
//--- Sep 22, 2013 crycat wrotes:
//--- никогда не понимал использование exceptions в C++, но раз уж есть, то пришлось не только
//--- сделать необходимый work around, но и подстроиться под стиль автора. допускаю что это было не очень красиво
//--- но мне лень переписывать на exception-free стиль всю программу, поэтому для одного пароля старый механизм
//--- а для перебора паролей из файла - флаг о недопустимости бросания exception'ов
    EmbData* embdata=NULL;

    if(Args.Passfile.is_set())
       {
        char        cstr[260]="";
        std::string passfile = Args.Passfile.getValue();
        char *fname=new char[passfile.length()+1];
        strcpy(fname, passfile.c_str());
        FILE       *fp=fopen64(fname,"rt"); // fopen оказывается не умеет в файлы > 2GB

        printf("Using '%s' passwords list file\n",fname);

        if(fp)
           {
            while(fgets(cstr,sizeof(cstr)-1,fp))
               {
                //--- режем переводы строки
                char *lf;
                if ((lf=strchr(cstr, '\n')) != NULL) *lf='\0';

                //--- назначем новый пароль и пытаемся расшифровать им
                //--- в случае фейла extractPass вернет NULL
                //--- в случае успеха получим указатель, который мы должны вернуть наверх
                Passphrase.assign(cstr);

                embdata=extractPass(true);
                if(embdata)
                   {
                    printf("Done with '%s' password\n",cstr);
                    break;
                   }
               }

            fclose(fp);
            //--- нас наверху ждет catch, так что по правилам этих сырцов бросим exception
            if(!embdata) throw SteghideError(_("could not find correct password using this passfile!"));
           }
        else throw SteghideError(_("could not open passwords list file"));
       }
    else embdata=extractPass(false); // стандартный механизм с одним паролем
//--- все что дальше это обычный механизм, сюда дойдет если пароль был найден
//--- потому что если не дойдет, то это exception выкинул наверх
	vd.printMessage() ;

// TODO (postponed due to message freeze): rename into "verifying crc32 checksum..."
    VerboseMessage vc(_("checking crc32 checksum..."));
    vc.setNewline (false);
    vc.printMessage();
    if(embdata->checksumOK()) { VerboseMessage vok(_(" ok")); vok.printMessage(); }
    else
       {
        VerboseMessage vfailed (_(" FAILED!")) ;
        vfailed.printMessage() ;

        CriticalWarning w (_("crc32 checksum failed! extracted data is probably corrupted.")) ;
        w.printMessage() ;
       }
//---
    return embdata ;
   }
//+-------------------------------------------------------------------------+
//| Непосредственно попытка расшифровки загруженного стегофайла             |
//+-------------------------------------------------------------------------+
EmbData* Extractor::extractPass(bool nothrow)
   {
    EmbData* embdata = new EmbData (EmbData::EXTRACT, Passphrase) ;
    Selector sel(Globs.TheCvrStgFile->getNumSamples(), Passphrase) ;
//---
    unsigned long sv_idx=0;

    while(!embdata->finished())
       {
        unsigned short bitsperembvalue = AUtils::log2_ceil<unsigned short> (Globs.TheCvrStgFile->getEmbValueModulus()) ;
        unsigned long embvaluesrequested = AUtils::div_roundup<unsigned long> (embdata->getNumBitsRequested(), bitsperembvalue) ;
        //---
        if(sv_idx+(Globs.TheCvrStgFile->getSamplesPerVertex()*embvaluesrequested)>=Globs.TheCvrStgFile->getNumSamples())
           {
            //--- в режиме перебора паролей, нам этот exception только помешает
            if(nothrow) { delete embdata; return(NULL); }
            //--- далее код автора стегхайда, кинул эксепшн и все закончилось
            //--- мне вот, кстати, интересно, а кто память освобождать будет?
            if(Globs.TheCvrStgFile->is_std())
               {
                throw CorruptDataError (_("the stego data from standard input is too short to contain the embedded data.")) ;
               }
            else
               {
                throw CorruptDataError (_("the stego file \"%s\" is too short to contain the embedded data."), Globs.TheCvrStgFile->getName().c_str()) ;
               }
           }

        BitString bits(Globs.TheCvrStgFile->getEmbValueModulus());
        for(unsigned long i = 0 ; i < embvaluesrequested ; i++)
           {
            EmbValue ev=0 ;
            for(unsigned int j=0;j<Globs.TheCvrStgFile->getSamplesPerVertex();j++,sv_idx++)
               {
                ev = (ev + Globs.TheCvrStgFile->getEmbeddedValue (sel[sv_idx])) % Globs.TheCvrStgFile->getEmbValueModulus() ;
               }
            bits.appendNAry(ev) ;
           }
        //--- опять же, в режиме перебора никаких exception
        if(nothrow)
           {
            try
               {
                embdata->addBits(bits);
               }
            catch(SteghideError& e)
               {
                delete embdata;
                return NULL;
               }
           }
        else  embdata->addBits (bits) ;
       }
//--- все ок, вернем дешфированные данные
    return(embdata);
   }
//+-------------------------------------------------------------------------+
