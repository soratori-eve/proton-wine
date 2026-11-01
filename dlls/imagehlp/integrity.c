/*
 *	IMAGEHLP library
 *
 *	Copyright 1998	Patrik Stridvall
 *	Copyright 2003	Mike McCormack
 *	Copyright 2009  Owen Rudge for CodeWeavers
 *	Copyright 2010  Juan Lang
 *	Copyright 2010  Andrey Turkin
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winternl.h"
#include "winnt.h"
#include "winver.h"
#include "imagehlp.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(imagehlp);

/*
 * These functions are partially documented at:
 *   http://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
 */

#define HDR_FAIL   -1
#define HDR_NT32    0
#define HDR_NT64    1

/***********************************************************************
 * IMAGEHLP_GetNTHeaders (INTERNAL)
 *
 * Return the IMAGE_NT_HEADERS for a PE file, after validating magic
 * numbers and distinguishing between 32-bit and 64-bit files.
 */
static int IMAGEHLP_GetNTHeaders(HANDLE handle, DWORD *pe_offset, IMAGE_NT_HEADERS32 *nt32, IMAGE_NT_HEADERS64 *nt64)
{
    IMAGE_DOS_HEADER dos_hdr;
    DWORD count;
    BOOL r;

    TRACE("handle %p\n", handle);

    if ((!nt32) || (!nt64))
        return HDR_FAIL;

    /* read the DOS header */
    count = SetFilePointer(handle, 0, NULL, FILE_BEGIN);

    if (count == INVALID_SET_FILE_POINTER)
        return HDR_FAIL;

    count = 0;

    r = ReadFile(handle, &dos_hdr, sizeof dos_hdr, &count, NULL);

    if (!r)
        return HDR_FAIL;

    if (count != sizeof dos_hdr)
        return HDR_FAIL;

    /* verify magic number of 'MZ' */
    if (dos_hdr.e_magic != IMAGE_DOS_SIGNATURE)
        return HDR_FAIL;

    if (pe_offset != NULL)
        *pe_offset = dos_hdr.e_lfanew;

    /* read the PE header */
    count = SetFilePointer(handle, dos_hdr.e_lfanew, NULL, FILE_BEGIN);

    if (count == INVALID_SET_FILE_POINTER)
        return HDR_FAIL;

    count = 0;

    r = ReadFile(handle, nt32, sizeof(IMAGE_NT_HEADERS32), &count, NULL);

    if (!r)
        return HDR_FAIL;

    if (count != sizeof(IMAGE_NT_HEADERS32))
        return HDR_FAIL;

    /* verify NT signature */
    if (nt32->Signature != IMAGE_NT_SIGNATURE)
        return HDR_FAIL;

    /* check if we have a 32-bit or 64-bit executable */
    switch (nt32->OptionalHeader.Magic)
    {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return HDR_NT32;

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            /* Re-read as 64-bit */

            count = SetFilePointer(handle, dos_hdr.e_lfanew, NULL, FILE_BEGIN);

            if (count == INVALID_SET_FILE_POINTER)
                return HDR_FAIL;

            count = 0;

            r = ReadFile(handle, nt64, sizeof(IMAGE_NT_HEADERS64), &count, NULL);

            if (!r)
                return HDR_FAIL;

            if (count != sizeof(IMAGE_NT_HEADERS64))
                return HDR_FAIL;

            /* verify NT signature */
            if (nt64->Signature != IMAGE_NT_SIGNATURE)
                return HDR_FAIL;

            return HDR_NT64;
    }

    return HDR_FAIL;
}

/***********************************************************************
 * IMAGEHLP_GetSecurityDirOffset (INTERNAL)
 *
 * Read a file's PE header, and return the offset and size of the
 *  security directory.
 */
static BOOL IMAGEHLP_GetSecurityDirOffset( HANDLE handle,
                                           DWORD *pdwOfs, DWORD *pdwSize )
{
    IMAGE_NT_HEADERS32 nt_hdr32;
    IMAGE_NT_HEADERS64 nt_hdr64;
    IMAGE_DATA_DIRECTORY *sd;
    int ret;

    ret = IMAGEHLP_GetNTHeaders(handle, NULL, &nt_hdr32, &nt_hdr64);

    if (ret == HDR_NT32)
        sd = &nt_hdr32.OptionalHeader.DataDirectory[IMAGE_FILE_SECURITY_DIRECTORY];
    else if (ret == HDR_NT64)
        sd = &nt_hdr64.OptionalHeader.DataDirectory[IMAGE_FILE_SECURITY_DIRECTORY];
    else
        return FALSE;

    TRACE("ret = %d size = %lx addr = %lx\n", ret, sd->Size, sd->VirtualAddress);

    *pdwSize = sd->Size;
    *pdwOfs = sd->VirtualAddress;

    return TRUE;
}

/***********************************************************************
 * IMAGEHLP_SetSecurityDirOffset (INTERNAL)
 *
 * Read a file's PE header, and update the offset and size of the
 *  security directory.
 */
static BOOL IMAGEHLP_SetSecurityDirOffset(HANDLE handle,
                                          DWORD dwOfs, DWORD dwSize)
{
    IMAGE_NT_HEADERS32 nt_hdr32;
    IMAGE_NT_HEADERS64 nt_hdr64;
    IMAGE_DATA_DIRECTORY *sd;
    int ret, nt_hdr_size = 0;
    DWORD pe_offset;
    void *nt_hdr;
    DWORD count;
    BOOL r;

    ret = IMAGEHLP_GetNTHeaders(handle, &pe_offset, &nt_hdr32, &nt_hdr64);

    if (ret == HDR_NT32)
    {
        sd = &nt_hdr32.OptionalHeader.DataDirectory[IMAGE_FILE_SECURITY_DIRECTORY];

        nt_hdr = &nt_hdr32;
        nt_hdr_size = sizeof(IMAGE_NT_HEADERS32);
    }
    else if (ret == HDR_NT64)
    {
        sd = &nt_hdr64.OptionalHeader.DataDirectory[IMAGE_FILE_SECURITY_DIRECTORY];

        nt_hdr = &nt_hdr64;
        nt_hdr_size = sizeof(IMAGE_NT_HEADERS64);
    }
    else
        return FALSE;

    sd->Size = dwSize;
    sd->VirtualAddress = dwOfs;

    TRACE("size = %lx addr = %lx\n", sd->Size, sd->VirtualAddress);

    /* write the header back again */
    count = SetFilePointer(handle, pe_offset, NULL, FILE_BEGIN);

    if (count == INVALID_SET_FILE_POINTER)
        return FALSE;

    count = 0;

    r = WriteFile(handle, nt_hdr, nt_hdr_size, &count, NULL);

    if (!r)
        return FALSE;

    if (count != nt_hdr_size)
        return FALSE;

    return TRUE;
}

/***********************************************************************
 * IMAGEHLP_GetCertificateOffset (INTERNAL)
 *
 * Read a file's PE header, and return the offset and size of the 
 *  security directory.
 */
static BOOL IMAGEHLP_GetCertificateOffset( HANDLE handle, DWORD num,
                                           DWORD *pdwOfs, DWORD *pdwSize )
{
    DWORD size, count, offset, len, sd_VirtualAddr;
    BOOL r;

    r = IMAGEHLP_GetSecurityDirOffset( handle, &sd_VirtualAddr, &size );
    if( !r )
        return FALSE;

    offset = 0;
    /* take the n'th certificate */
    while( 1 )
    {
        /* read the length of the current certificate */
        count = SetFilePointer( handle, sd_VirtualAddr + offset,
                                 NULL, FILE_BEGIN );
        if( count == INVALID_SET_FILE_POINTER )
            return FALSE;
        r = ReadFile( handle, &len, sizeof len, &count, NULL );
        if( !r )
            return FALSE;
        if( count != sizeof len )
            return FALSE;

        /* check the certificate is not too big or too small */
        if( len < sizeof len )
            return FALSE;
        if( len > (size-offset) )
            return FALSE;
        if( !num-- )
            break;

        /* calculate the offset of the next certificate */
        offset += len;

        /* padded out to the nearest 8-byte boundary */
        if( len % 8 )
            offset += 8 - (len % 8);

        if( offset >= size )
            return FALSE;
    }

    *pdwOfs = sd_VirtualAddr + offset;
    *pdwSize = len;

    TRACE("len = %lx addr = %lx\n", len, sd_VirtualAddr + offset);

    return TRUE;
}

/***********************************************************************
 * IMAGEHLP_RecalculateChecksum (INTERNAL)
 *
 * Update the NT header checksum for the specified file.
 */
static BOOL IMAGEHLP_RecalculateChecksum(HANDLE handle)
{
    DWORD FileLength, count, HeaderSum, pe_offset, nt_hdr_size;
    IMAGE_NT_HEADERS32 nt_hdr32;
    IMAGE_NT_HEADERS64 nt_hdr64;
    LPVOID BaseAddress;
    HANDLE hMapping;
    DWORD *CheckSum;
    void *nt_hdr;
    int ret;
    BOOL r;

    TRACE("handle %p\n", handle);

    ret = IMAGEHLP_GetNTHeaders(handle, &pe_offset, &nt_hdr32, &nt_hdr64);

    if (ret == HDR_NT32)
    {
        CheckSum = &nt_hdr32.OptionalHeader.CheckSum;

        nt_hdr = &nt_hdr32;
        nt_hdr_size = sizeof(IMAGE_NT_HEADERS32);
    }
    else if (ret == HDR_NT64)
    {
        CheckSum = &nt_hdr64.OptionalHeader.CheckSum;

        nt_hdr = &nt_hdr64;
        nt_hdr_size = sizeof(IMAGE_NT_HEADERS64);
    }
    else
        return FALSE;

    hMapping = CreateFileMappingW(handle, NULL, PAGE_READONLY, 0, 0, NULL);

    if (!hMapping)
        return FALSE;

    BaseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    if (!BaseAddress)
    {
        CloseHandle(hMapping);
        return FALSE;
    }

    FileLength = GetFileSize(handle, NULL);

    *CheckSum = 0;
    CheckSumMappedFile(BaseAddress, FileLength, &HeaderSum, CheckSum);

    UnmapViewOfFile(BaseAddress);
    CloseHandle(hMapping);

    if (*CheckSum)
    {
        /* write the header back again */
        count = SetFilePointer(handle, pe_offset, NULL, FILE_BEGIN);

        if (count == INVALID_SET_FILE_POINTER)
            return FALSE;

        count = 0;

        r = WriteFile(handle, nt_hdr, nt_hdr_size, &count, NULL);

        if (!r)
            return FALSE;

        if (count != nt_hdr_size)
            return FALSE;

        return TRUE;
    }

    return FALSE;
}

/***********************************************************************
 *		ImageAddCertificate (IMAGEHLP.@)
 *
 * Adds the specified certificate to the security directory of
 * open PE file.
 */

BOOL WINAPI ImageAddCertificate(
  HANDLE FileHandle, LPWIN_CERTIFICATE Certificate, PDWORD Index)
{
    DWORD size = 0, count = 0, offset = 0, sd_VirtualAddr = 0, index = 0;
    WIN_CERTIFICATE hdr;
    const size_t cert_hdr_size = sizeof hdr - sizeof hdr.bCertificate;
    BOOL r;

    TRACE("(%p, %p, %p)\n", FileHandle, Certificate, Index);

    r = IMAGEHLP_GetSecurityDirOffset(FileHandle, &sd_VirtualAddr, &size);

    /* If we've already got a security directory, find the end of it */
    if ((r) && (sd_VirtualAddr != 0))
    {
        /* Check if the security directory is at the end of the file.
           If not, we should probably relocate it. */
        if (GetFileSize(FileHandle, NULL) != sd_VirtualAddr + size)
        {
            FIXME("Security directory already present but not located at EOF, not adding certificate\n");

            SetLastError(ERROR_NOT_SUPPORTED);
            return FALSE;
        }

        while (offset < size)
        {
            /* read the length of the current certificate */
            count = SetFilePointer (FileHandle, sd_VirtualAddr + offset,
                                     NULL, FILE_BEGIN);

            if (count == INVALID_SET_FILE_POINTER)
                return FALSE;

            r = ReadFile(FileHandle, &hdr, cert_hdr_size, &count, NULL);

            if (!r)
                return FALSE;

            if (count != cert_hdr_size)
                return FALSE;

            /* check the certificate is not too big or too small */
            if (hdr.dwLength < cert_hdr_size)
                return FALSE;

            if (hdr.dwLength > (size-offset))
                return FALSE;

            /* next certificate */
            offset += hdr.dwLength;

            /* padded out to the nearest 8-byte boundary */
            if (hdr.dwLength % 8)
                offset += 8 - (hdr.dwLength % 8);

            index++;
        }

        count = SetFilePointer (FileHandle, sd_VirtualAddr + offset, NULL, FILE_BEGIN);

        if (count == INVALID_SET_FILE_POINTER)
            return FALSE;
    }
    else
    {
        sd_VirtualAddr = SetFilePointer(FileHandle, 0, NULL, FILE_END);

        if (sd_VirtualAddr == INVALID_SET_FILE_POINTER)
            return FALSE;
    }

    /* Write the certificate to the file */
    r = WriteFile(FileHandle, Certificate, Certificate->dwLength, &count, NULL);

    if (!r)
        return FALSE;

    /* Pad out if necessary */
    if (Certificate->dwLength % 8)
    {
        char null[8];

        ZeroMemory(null, 8);
        WriteFile(FileHandle, null, 8 - (Certificate->dwLength % 8), &count, NULL);

        size += 8 - (Certificate->dwLength % 8);
    }

    size += Certificate->dwLength;

    /* Update the security directory offset and size */
    if (!IMAGEHLP_SetSecurityDirOffset(FileHandle, sd_VirtualAddr, size))
        return FALSE;

    if (!IMAGEHLP_RecalculateChecksum(FileHandle))
        return FALSE;

    if(Index)
        *Index = index;
    return TRUE;
}

/***********************************************************************
 *		ImageEnumerateCertificates (IMAGEHLP.@)
 */
BOOL WINAPI ImageEnumerateCertificates(
    HANDLE handle, WORD TypeFilter, PDWORD CertificateCount,
    PDWORD Indices, DWORD IndexCount)
{
    DWORD size, count, offset, sd_VirtualAddr, index;
    WIN_CERTIFICATE hdr;
    const size_t cert_hdr_size = sizeof hdr - sizeof hdr.bCertificate;
    BOOL r;

    TRACE("%p %hd %p %p %ld\n",
           handle, TypeFilter, CertificateCount, Indices, IndexCount);

    r = IMAGEHLP_GetSecurityDirOffset( handle, &sd_VirtualAddr, &size );
    if( !r )
        return FALSE;

    offset = 0;
    index = 0;
    *CertificateCount = 0;
    while( offset < size )
    {
        /* read the length of the current certificate */
        count = SetFilePointer( handle, sd_VirtualAddr + offset,
                                 NULL, FILE_BEGIN );
        if( count == INVALID_SET_FILE_POINTER )
            return FALSE;
        r = ReadFile( handle, &hdr, cert_hdr_size, &count, NULL );
        if( !r )
            return FALSE;
        if( count != cert_hdr_size )
            return FALSE;

        TRACE("Size = %08lx  id = %08hx\n",
               hdr.dwLength, hdr.wCertificateType );

        /* check the certificate is not too big or too small */
        if( hdr.dwLength < cert_hdr_size )
            return FALSE;
        if( hdr.dwLength > (size-offset) )
            return FALSE;
       
        if( (TypeFilter == CERT_SECTION_TYPE_ANY) ||
            (TypeFilter == hdr.wCertificateType) )
        {
            (*CertificateCount)++;
            if(Indices && *CertificateCount <= IndexCount)
                *Indices++ = index;
        }

        /* next certificate */
        offset += hdr.dwLength;

        /* padded out to the nearest 8-byte boundary */
        if (hdr.dwLength % 8)
            offset += 8 - (hdr.dwLength % 8);

        index++;
    }

    return TRUE;
}

/***********************************************************************
 *		ImageGetCertificateData (IMAGEHLP.@)
 *
 *  FIXME: not sure that I'm dealing with the Index the right way
 */
BOOL WINAPI ImageGetCertificateData(
                HANDLE handle, DWORD Index,
                LPWIN_CERTIFICATE Certificate, PDWORD RequiredLength)
{
    DWORD r, offset, ofs, size, count;

    TRACE("%p %ld %p %p\n", handle, Index, Certificate, RequiredLength);

    if( !RequiredLength)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

    if( !IMAGEHLP_GetCertificateOffset( handle, Index, &ofs, &size ) )
        return FALSE;

    if( *RequiredLength < size )
    {
        *RequiredLength = size;
        SetLastError( ERROR_INSUFFICIENT_BUFFER );
        return FALSE;
    }

    if( !Certificate )
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

    *RequiredLength = size;

    offset = SetFilePointer( handle, ofs, NULL, FILE_BEGIN );
    if( offset == INVALID_SET_FILE_POINTER )
        return FALSE;

    r = ReadFile( handle, Certificate, size, &count, NULL );
    if( !r )
        return FALSE;
    if( count != size )
        return FALSE;

    TRACE("OK\n");
    SetLastError( NO_ERROR );

    return TRUE;
}

/***********************************************************************
 *		ImageGetCertificateHeader (IMAGEHLP.@)
 */
BOOL WINAPI ImageGetCertificateHeader(
    HANDLE handle, DWORD index, LPWIN_CERTIFICATE pCert)
{
    DWORD r, offset, ofs, size, count;
    const size_t cert_hdr_size = sizeof *pCert - sizeof pCert->bCertificate;

    TRACE("%p %ld %p\n", handle, index, pCert);

    if( !IMAGEHLP_GetCertificateOffset( handle, index, &ofs, &size ) )
        return FALSE;

    if( size < cert_hdr_size )
        return FALSE;

    offset = SetFilePointer( handle, ofs, NULL, FILE_BEGIN );
    if( offset == INVALID_SET_FILE_POINTER )
        return FALSE;

    r = ReadFile( handle, pCert, cert_hdr_size, &count, NULL );
    if( !r )
        return FALSE;
    if( count != cert_hdr_size )
        return FALSE;

    TRACE("OK\n");

    return TRUE;
}

/* Calls DigestFunction e bytes at offset offset from the file mapped at map.
 * Returns the return value of DigestFunction, or FALSE if the data is not available.
 */
static BOOL IMAGEHLP_ReportSectionFromOffset( DWORD offset, DWORD size,
    BYTE *map, DWORD fileSize, DIGEST_FUNCTION DigestFunction, DIGEST_HANDLE DigestHandle )
{
    if( offset + size > fileSize )
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return DigestFunction( DigestHandle, map + offset, size );
}

/* The helpers below reproduce how native Windows builds the byte stream
 * returned by ImageGetDigestStream():
 *
 *  - The certificate table directory entry and the checksum are always
 *    cleared in the reported NT headers.
 *  - Unless CERT_PE_IMAGE_DIGEST_RESOURCES is set, the resource directory is
 *    cleared, together with the whole header of the section holding the
 *    resources.  The resource data itself is left out of the stream (any
 *    padding of the section is still reported).
 *  - Unless CERT_PE_IMAGE_DIGEST_DEBUG_INFO is set, the section named ".debug"
 *    is left out and its header cleared.
 *  - When either of the two above applies (for the debug case, only if there is
 *    a ".debug" section), SizeOfInitializedData, SizeOfImage, the base relocation
 *    directory address and the address and file offset of the section holding
 *    the base relocations are cleared too.
 *  - Unless CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO is set, the TimeDateStamp and
 *    ForwarderChain fields of the import descriptors and the import address
 *    table are left out.  The IAT is taken from the IAT data directory when
 *    there is one, and from the FirstThunk arrays of the import descriptors
 *    (including their null terminator) otherwise.
 *  - Sections are reported in the order of the section table, code sections
 *    first.  Left out ranges split a section into several updates.
 */

struct digest_range
{
    DWORD start;
    DWORD end;
};

struct digest_ranges
{
    struct digest_range *ranges;
    DWORD count;
    DWORD size;
};

static BOOL digest_ranges_add( struct digest_ranges *r, DWORD start, DWORD end )
{
    if (end <= start) return TRUE;
    if (r->count == r->size)
    {
        DWORD new_size = r->size ? r->size * 2 : 64;
        struct digest_range *new_ranges;

        if (r->ranges) new_ranges = HeapReAlloc( GetProcessHeap(), 0, r->ranges, new_size * sizeof(*new_ranges) );
        else new_ranges = HeapAlloc( GetProcessHeap(), 0, new_size * sizeof(*new_ranges) );
        if (!new_ranges) return FALSE;
        r->ranges = new_ranges;
        r->size = new_size;
    }
    r->ranges[r->count].start = start;
    r->ranges[r->count].end = end;
    r->count++;
    return TRUE;
}

static void digest_ranges_sort( struct digest_ranges *r )
{
    DWORD i, j, n = 0;

    if (!r->count) return;
    /* insertion sort, the number of ranges is small */
    for (i = 1; i < r->count; i++)
    {
        struct digest_range tmp = r->ranges[i];

        for (j = i; j > 0 && r->ranges[j - 1].start > tmp.start; j--) r->ranges[j] = r->ranges[j - 1];
        r->ranges[j] = tmp;
    }
    for (i = 1; i < r->count; i++)
    {
        if (r->ranges[i].start <= r->ranges[n].end)
        {
            if (r->ranges[i].end > r->ranges[n].end) r->ranges[n].end = r->ranges[i].end;
        }
        else r->ranges[++n] = r->ranges[i];
    }
    r->count = n + 1;
}

/* Converts a RVA to an offset in the file, or returns FALSE if there is no
 * raw data for it. */
static BOOL IMAGEHLP_RvaToOffset( const IMAGE_SECTION_HEADER *hdr, DWORD num_sections,
    DWORD fileSize, DWORD rva, DWORD *offset )
{
    DWORD i;

    for (i = 0; i < num_sections; i++, hdr++)
    {
        if (rva >= hdr->VirtualAddress && rva - hdr->VirtualAddress < hdr->SizeOfRawData)
        {
            *offset = hdr->PointerToRawData + (rva - hdr->VirtualAddress);
            return *offset < fileSize;
        }
    }
    return FALSE;
}

/* Collects the RVA ranges of the import information that is not part of the
 * stream unless CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO is set. */
static BOOL IMAGEHLP_CollectImportRanges( const IMAGE_SECTION_HEADER *hdr, DWORD num_sections,
    const BYTE *map, DWORD fileSize, BOOL is64, const IMAGE_DATA_DIRECTORY *import_dir,
    const IMAGE_DATA_DIRECTORY *iat_dir, struct digest_ranges *ranges )
{
    const DWORD thunk_size = is64 ? sizeof(ULONGLONG) : sizeof(DWORD);
    DWORD i, rva, offset;

    if (iat_dir && iat_dir->VirtualAddress && iat_dir->Size)
    {
        if (!digest_ranges_add( ranges, iat_dir->VirtualAddress, iat_dir->VirtualAddress + iat_dir->Size ))
            return FALSE;
        iat_dir = NULL;  /* already handled, don't walk the FirstThunk arrays */
    }
    else iat_dir = import_dir;  /* marker: walk the FirstThunk arrays */

    if (!import_dir || !import_dir->VirtualAddress) return TRUE;

    for (i = 0; i < 0x1000; i++)
    {
        const IMAGE_IMPORT_DESCRIPTOR *desc;

        rva = import_dir->VirtualAddress + i * sizeof(*desc);
        if (!IMAGEHLP_RvaToOffset( hdr, num_sections, fileSize, rva, &offset ) ||
            offset + sizeof(*desc) > fileSize)
            break;
        desc = (const IMAGE_IMPORT_DESCRIPTOR *)(map + offset);
        if (!desc->OriginalFirstThunk && !desc->TimeDateStamp && !desc->ForwarderChain &&
            !desc->Name && !desc->FirstThunk)
            break;

        /* TimeDateStamp and ForwarderChain */
        if (!digest_ranges_add( ranges, rva + FIELD_OFFSET(IMAGE_IMPORT_DESCRIPTOR, TimeDateStamp),
                                rva + FIELD_OFFSET(IMAGE_IMPORT_DESCRIPTOR, Name) ))
            return FALSE;

        if (iat_dir && desc->FirstThunk)
        {
            /* IAT of this descriptor, including the terminating null thunk */
            DWORD thunk_rva = desc->FirstThunk, n = 0, thunk_offset;

            for (;;)
            {
                ULONGLONG thunk = 0;

                if (!IMAGEHLP_RvaToOffset( hdr, num_sections, fileSize, thunk_rva + n * thunk_size,
                                           &thunk_offset ) ||
                    thunk_offset + thunk_size > fileSize)
                    break;
                memcpy( &thunk, map + thunk_offset, thunk_size );
                n++;
                if (!thunk) break;
            }
            if (!digest_ranges_add( ranges, thunk_rva, thunk_rva + n * thunk_size )) return FALSE;
        }
    }
    return TRUE;
}

/* Reports a section, leaving out the parts of it covered by the given sorted
 * and merged RVA ranges. */
static BOOL IMAGEHLP_ReportSectionRanges( const IMAGE_SECTION_HEADER *hdr, const struct digest_ranges *ranges,
    BYTE *map, DWORD fileSize, DIGEST_FUNCTION DigestFunction, DIGEST_HANDLE DigestHandle )
{
    DWORD start = hdr->VirtualAddress, end = start + hdr->SizeOfRawData, pos = start, i;
    BOOL ret;

    for (i = 0; i < ranges->count; i++)
    {
        DWORD s = ranges->ranges[i].start, e = ranges->ranges[i].end;

        if (e <= pos) continue;
        if (s >= end) break;
        if (s > pos)
        {
            ret = IMAGEHLP_ReportSectionFromOffset( hdr->PointerToRawData + (pos - start), s - pos,
                                                    map, fileSize, DigestFunction, DigestHandle );
            if (!ret) return FALSE;
        }
        pos = e;
        if (pos >= end) return TRUE;
    }
    if (pos < end)
        return IMAGEHLP_ReportSectionFromOffset( hdr->PointerToRawData + (pos - start), end - pos,
                                                 map, fileSize, DigestFunction, DigestHandle );
    return TRUE;
}

static BOOL IMAGEHLP_IsDebugSection( const IMAGE_SECTION_HEADER *hdr )
{
    return !memcmp( hdr->Name, ".debug\0\0", IMAGE_SIZEOF_SHORT_NAME );
}

static BOOL IMAGEHLP_SectionContainsRva( const IMAGE_SECTION_HEADER *hdr, DWORD rva )
{
    return rva >= hdr->VirtualAddress && rva - hdr->VirtualAddress < max( hdr->Misc.VirtualSize, hdr->SizeOfRawData );
}

/***********************************************************************
 *		ImageGetDigestStream (IMAGEHLP.@)
 *
 * Gets a stream of bytes from a PE file over which a hash might be computed to
 * verify that the image has not changed.  Useful for creating a certificate to
 * be added to the file with ImageAddCertificate.
 *
 * PARAMS
 *  FileHandle     [In] File for which to return a stream.
 *  DigestLevel    [In] Flags to control which portions of the file to return.
 *                      0 is allowed, as is any combination of:
 *                       CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO: reports the entire
 *                        import information rather than selected portions of it.
 *                       CERT_PE_IMAGE_DIGEST_DEBUG_INFO: reports the debug section.
 *                       CERT_PE_IMAGE_DIGEST_RESOURCES: reports the resources
 *                        and the fields of the headers that depend on them.
 *  DigestFunction [In] Callback function.
 *  DigestHandle   [In] Handle passed as first parameter to DigestFunction.
 *
 * RETURNS
 *  TRUE if successful.
 *  FALSE if unsuccessful.  GetLastError returns more about the error.
 *
 * NOTES
 *  Reports data in the following order:
 *  1. The DOS header and stub, the NT headers and the section headers.
 *  2. Any code sections.
 *  3. All the other sections, in the order of the section table.
 *  See the comment above for what is left out or cleared.
 */
BOOL WINAPI ImageGetDigestStream(
  HANDLE FileHandle, DWORD DigestLevel,
  DIGEST_FUNCTION DigestFunction, DIGEST_HANDLE DigestHandle)
{
    DWORD error = 0;
    BOOL ret = FALSE, is64, has_debug = FALSE, clear_layout;
    DWORD offset, size, num_sections, fileSize, i, num_dirs;
    HANDLE hMap = INVALID_HANDLE_VALUE;
    BYTE *map = NULL;
    IMAGE_DOS_HEADER *dos_hdr;
    IMAGE_NT_HEADERS32 *nt32;
    IMAGE_NT_HEADERS64 *nt64;
    IMAGE_FILE_HEADER *file_hdr;
    IMAGE_DATA_DIRECTORY *dirs;
    IMAGE_SECTION_HEADER *section_headers, *sections = NULL;
    struct digest_ranges ranges = { NULL, 0, 0 };
    IMAGE_DATA_DIRECTORY import_dir, iat_dir, res_dir, reloc_dir;
    DWORD dir_offset;

    TRACE("(%p, %ld, %p, %p)\n", FileHandle, DigestLevel, DigestFunction,
        DigestHandle);

    /* Get the file size */
    if( !FileHandle )
        goto invalid_parameter;
    fileSize = GetFileSize( FileHandle, NULL );
    if(fileSize == INVALID_FILE_SIZE )
        goto invalid_parameter;

    /* map file */
    hMap = CreateFileMappingW( FileHandle, NULL, PAGE_READONLY, 0, 0, NULL );
    if( hMap == INVALID_HANDLE_VALUE )
        goto invalid_parameter;
    map = MapViewOfFile( hMap, FILE_MAP_COPY, 0, 0, 0 );
    if( !map )
        goto invalid_parameter;

    /* Read the file header */
    if( fileSize < sizeof(IMAGE_DOS_HEADER) )
        goto invalid_parameter;
    dos_hdr = (IMAGE_DOS_HEADER *)map;

    if( dos_hdr->e_magic != IMAGE_DOS_SIGNATURE )
        goto invalid_parameter;
    offset = dos_hdr->e_lfanew;
    if( !offset || offset > fileSize )
        goto invalid_parameter;
    ret = DigestFunction( DigestHandle, map, offset );
    if( !ret )
        goto end;

    /* Read the NT header, which is either the 32-bit or the 64-bit one */
    if( offset + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.Magic) + sizeof(WORD) > fileSize )
        goto invalid_parameter;
    nt32 = (IMAGE_NT_HEADERS32 *)(map + offset);
    nt64 = (IMAGE_NT_HEADERS64 *)(map + offset);
    if( nt32->Signature != IMAGE_NT_SIGNATURE )
        goto invalid_parameter;
    file_hdr = &nt32->FileHeader;
    is64 = nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if( is64 )
    {
        if( offset + sizeof(IMAGE_NT_HEADERS64) > fileSize ||
            file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) - sizeof(nt64->OptionalHeader.DataDirectory) )
            goto invalid_parameter;
        dirs = nt64->OptionalHeader.DataDirectory;
        num_dirs = nt64->OptionalHeader.NumberOfRvaAndSizes;
        dir_offset = FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory);
    }
    else
    {
        if( offset + sizeof(IMAGE_NT_HEADERS32) > fileSize ||
            file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32) - sizeof(nt32->OptionalHeader.DataDirectory) )
            goto invalid_parameter;
        dirs = nt32->OptionalHeader.DataDirectory;
        num_dirs = nt32->OptionalHeader.NumberOfRvaAndSizes;
        dir_offset = FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory);
    }
    /* only use the directories that are inside the optional header */
    if( (DWORD)(file_hdr->SizeOfOptionalHeader + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader)) < dir_offset )
        num_dirs = 0;
    else
        num_dirs = min( num_dirs, (file_hdr->SizeOfOptionalHeader + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) - dir_offset) /
                                  sizeof(IMAGE_DATA_DIRECTORY) );
    num_dirs = min( num_dirs, IMAGE_NUMBEROF_DIRECTORY_ENTRIES );

    memset( &import_dir, 0, sizeof(import_dir) );
    memset( &iat_dir, 0, sizeof(iat_dir) );
    memset( &res_dir, 0, sizeof(res_dir) );
    memset( &reloc_dir, 0, sizeof(reloc_dir) );
    if( num_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT ) import_dir = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if( num_dirs > IMAGE_DIRECTORY_ENTRY_IAT ) iat_dir = dirs[IMAGE_DIRECTORY_ENTRY_IAT];
    if( num_dirs > IMAGE_DIRECTORY_ENTRY_RESOURCE ) res_dir = dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if( num_dirs > IMAGE_DIRECTORY_ENTRY_BASERELOC ) reloc_dir = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    /* Read the section headers.  A copy of the original ones is kept since the
     * ones that get reported may be modified below. */
    size = sizeof(nt32->Signature) + sizeof(nt32->FileHeader) + file_hdr->SizeOfOptionalHeader;
    num_sections = file_hdr->NumberOfSections;
    if( offset + size + num_sections * sizeof(IMAGE_SECTION_HEADER) > fileSize )
        goto invalid_parameter;
    section_headers = (IMAGE_SECTION_HEADER *)(map + offset + size);
    if( num_sections )
    {
        sections = HeapAlloc( GetProcessHeap(), 0, num_sections * sizeof(*sections) );
        if( !sections )
        {
            error = ERROR_OUTOFMEMORY;
            goto end;
        }
        memcpy( sections, section_headers, num_sections * sizeof(*sections) );
    }

    /* The checksum and the certificate table are never part of the stream */
    if( is64 ) nt64->OptionalHeader.CheckSum = 0;
    else nt32->OptionalHeader.CheckSum = 0;
    if( num_dirs > IMAGE_DIRECTORY_ENTRY_SECURITY )
    {
        dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
        dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
    }

    /* The fields that depend on the layout of the image are cleared when the
     * resources are left out, or when a ".debug" section is left out. */
    for( i = 0; i < num_sections; i++ )
        if( IMAGEHLP_IsDebugSection( &sections[i] )) has_debug = TRUE;
    clear_layout = !(DigestLevel & CERT_PE_IMAGE_DIGEST_RESOURCES) ||
                   (has_debug && !(DigestLevel & CERT_PE_IMAGE_DIGEST_DEBUG_INFO));
    if( clear_layout )
    {
        if( is64 )
        {
            nt64->OptionalHeader.SizeOfInitializedData = 0;
            nt64->OptionalHeader.SizeOfImage = 0;
        }
        else
        {
            nt32->OptionalHeader.SizeOfInitializedData = 0;
            nt32->OptionalHeader.SizeOfImage = 0;
        }
        if( num_dirs > IMAGE_DIRECTORY_ENTRY_BASERELOC )
            dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    }
    if( !(DigestLevel & CERT_PE_IMAGE_DIGEST_RESOURCES) && num_dirs > IMAGE_DIRECTORY_ENTRY_RESOURCE )
    {
        dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0;
        dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0;
    }

    /* Clear the headers of the sections whose contents are not reported */
    for( i = 0; i < num_sections; i++ )
    {
        BOOL clear = FALSE;

        if( !(DigestLevel & CERT_PE_IMAGE_DIGEST_DEBUG_INFO) && IMAGEHLP_IsDebugSection( &sections[i] ))
            clear = TRUE;
        if( !(DigestLevel & CERT_PE_IMAGE_DIGEST_RESOURCES) )
        {
            if( res_dir.VirtualAddress && res_dir.Size &&
                res_dir.VirtualAddress >= sections[i].VirtualAddress &&
                res_dir.VirtualAddress - sections[i].VirtualAddress + res_dir.Size <= sections[i].Misc.VirtualSize )
                clear = TRUE;
        }
        if( clear_layout && reloc_dir.VirtualAddress &&
            IMAGEHLP_SectionContainsRva( &sections[i], reloc_dir.VirtualAddress ))
        {
            section_headers[i].VirtualAddress = 0;
            section_headers[i].PointerToRawData = 0;
        }
        if( clear )
        {
            section_headers[i].Misc.VirtualSize = 0;
            section_headers[i].VirtualAddress = 0;
            section_headers[i].SizeOfRawData = 0;
            section_headers[i].PointerToRawData = 0;
        }
    }

    ret = DigestFunction( DigestHandle, map + offset, size );
    if( !ret )
        goto end;
    ret = DigestFunction( DigestHandle, (BYTE *)section_headers, num_sections * sizeof(IMAGE_SECTION_HEADER) );
    if( !ret )
        goto end;

    /* Collect what is left out of the sections */
    if( !(DigestLevel & CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO) )
    {
        if( !IMAGEHLP_CollectImportRanges( sections, num_sections, map, fileSize, is64,
                                           &import_dir, &iat_dir, &ranges ))
        {
            error = ERROR_OUTOFMEMORY;
            ret = FALSE;
            goto end;
        }
    }
    if( !(DigestLevel & CERT_PE_IMAGE_DIGEST_RESOURCES) && res_dir.VirtualAddress && res_dir.Size )
    {
        if( !digest_ranges_add( &ranges, res_dir.VirtualAddress, res_dir.VirtualAddress + res_dir.Size ))
        {
            error = ERROR_OUTOFMEMORY;
            ret = FALSE;
            goto end;
        }
    }
    digest_ranges_sort( &ranges );

    /* Code sections first, then everything else in the order of the section table */
    for( i = 0; i < num_sections; i++ )
    {
        if( !(sections[i].Characteristics & IMAGE_SCN_CNT_CODE) || !sections[i].SizeOfRawData ) continue;
        IMAGEHLP_ReportSectionRanges( &sections[i], &ranges, map, fileSize, DigestFunction, DigestHandle );
    }
    for( i = 0; i < num_sections; i++ )
    {
        if( (sections[i].Characteristics & IMAGE_SCN_CNT_CODE) || !sections[i].SizeOfRawData ) continue;
        if( !(DigestLevel & CERT_PE_IMAGE_DIGEST_DEBUG_INFO) && IMAGEHLP_IsDebugSection( &sections[i] )) continue;
        IMAGEHLP_ReportSectionRanges( &sections[i], &ranges, map, fileSize, DigestFunction, DigestHandle );
    }

end:
    HeapFree( GetProcessHeap(), 0, ranges.ranges );
    HeapFree( GetProcessHeap(), 0, sections );
    if( map )
        UnmapViewOfFile( map );
    if( hMap != INVALID_HANDLE_VALUE )
        CloseHandle( hMap );
    if( error )
        SetLastError(error);
    return ret;

invalid_parameter:
    error = ERROR_INVALID_PARAMETER;
    goto end;
}

/***********************************************************************
 *		ImageRemoveCertificate (IMAGEHLP.@)
 */
BOOL WINAPI ImageRemoveCertificate(HANDLE FileHandle, DWORD Index)
{
    DWORD size = 0, count = 0, sd_VirtualAddr = 0, offset = 0;
    DWORD data_size = 0, cert_size = 0, cert_size_padded = 0, ret = 0;
    LPVOID cert_data;
    BOOL r;

    TRACE("(%p, %ld)\n", FileHandle, Index);

    r = ImageEnumerateCertificates(FileHandle, CERT_SECTION_TYPE_ANY, &count, NULL, 0);

    if ((!r) || (count == 0))
        return FALSE;

    if ((!IMAGEHLP_GetSecurityDirOffset(FileHandle, &sd_VirtualAddr, &size)) ||
        (!IMAGEHLP_GetCertificateOffset(FileHandle, Index, &offset, &cert_size)))
        return FALSE;

    /* Ignore any padding we have, too */
    if (cert_size % 8)
        cert_size_padded = cert_size + (8 - (cert_size % 8));
    else
        cert_size_padded = cert_size;

    data_size = size - (offset - sd_VirtualAddr) - cert_size_padded;

    if (data_size == 0)
    {
        ret = SetFilePointer(FileHandle, sd_VirtualAddr, NULL, FILE_BEGIN);

        if (ret == INVALID_SET_FILE_POINTER)
            return FALSE;
    }
    else
    {
        cert_data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, data_size);

        if (!cert_data)
            return FALSE;

        ret = SetFilePointer(FileHandle, offset + cert_size_padded, NULL, FILE_BEGIN);

        if (ret == INVALID_SET_FILE_POINTER)
            goto error;

        /* Read any subsequent certificates */
        r = ReadFile(FileHandle, cert_data, data_size, &count, NULL);

        if ((!r) || (count != data_size))
            goto error;

        SetFilePointer(FileHandle, offset, NULL, FILE_BEGIN);

        /* Write them one index back */
        r = WriteFile(FileHandle, cert_data, data_size, &count, NULL);

        if ((!r) || (count != data_size))
            goto error;

        HeapFree(GetProcessHeap(), 0, cert_data);
    }

    /* If security directory is at end of file, trim the file */
    if (GetFileSize(FileHandle, NULL) == sd_VirtualAddr + size)
        SetEndOfFile(FileHandle);

    if (count == 1)
        r = IMAGEHLP_SetSecurityDirOffset(FileHandle, 0, 0);
    else
        r = IMAGEHLP_SetSecurityDirOffset(FileHandle, sd_VirtualAddr, size - cert_size_padded);

    if (!r)
        return FALSE;

    if (!IMAGEHLP_RecalculateChecksum(FileHandle))
        return FALSE;

    return TRUE;

error:
    HeapFree(GetProcessHeap(), 0, cert_data);
    return FALSE;
}
