#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <IOKit/IOKitLib.h>
#import "IOKit/hid/IOHIDManager.h"
#import "IOKit/hid/IOHIDKeys.h"


/*
This is an example of how to target a specific IOKit device.
This should connect to the Yubikey device if it is present.
Build with $gcc -o yubi_kill main.c -framework IOKit -framework CoreFoundation
 
--FG
@iamreallyfrank
*/

int main(){
    kern_return_t err;
    
    //mach_vm_address_t addr32 = 0x41414141;
    mach_vm_address_t addr64 = 0x4242424242424242;
    mach_vm_size_t size = 0x0400;
    
    int i;
    int j;
    
    // Create an HID Manager
    IOHIDManagerRef HIDManager = IOHIDManagerCreate(kCFAllocatorDefault,
                                                    kIOHIDOptionsTypeNone);
    
    // Create a Matching Dictionary
    CFMutableDictionaryRef matchDict = CFDictionaryCreateMutable(
                                                                 kCFAllocatorDefault,
                                                                 2,
                                                                 &kCFTypeDictionaryKeyCallBacks,
                                                                 &kCFTypeDictionaryValueCallBacks);
    
    // Specify a device manufacturer in the Matching Dictionary
    CFDictionarySetValue(matchDict,
                         CFSTR(kIOHIDManufacturerKey),
                         CFSTR("Yubico"));

    // Open the HID Manager
    IOReturn IOReturn = IOHIDManagerOpen(HIDManager, kIOHIDOptionsTypeNone);
    if(IOReturn) printf("IOHIDManagerOpen failed."); // Couldn't open the HID manager!

    if(!matchDict){
        printf("[x] Error, unable to create service matching dictionary\r\n");
        return 0;
    }
    
    io_iterator_t iterator;
    err = IOServiceGetMatchingServices(kIOMasterPortDefault, matchDict, &iterator);
    
    if (err != KERN_SUCCESS){
        printf("[x] Error, Iterator found no matches\r\n");
        return 0;
    }
    
    io_service_t service = IOIteratorNext(iterator);
    
    if (service == IO_OBJECT_NULL){
        printf("[x] Error, unable to find service: %x\r\n", service);
        return 0;
    }
    printf("[i] Successfully got service: %x\n", service);

    
//Connect Type
for (j=0; j<=1000; j++)
{
    io_connect_t conn = MACH_MSG_ALLOCATE;
    //fprintf(fp, "[i] Fuzzing IOServiceOpen type %d with\r\n", j);
    err = IOServiceOpen(service, mach_task_self(), j, &conn);
    
    if (err != KERN_SUCCESS)
    {
        printf("[x] Unable to get user client connection with type %d\r\n", j);
        //return 0;
    }
    
    else
    {
        printf("[i] Successfully got userclient connection: %x with type %d\r\n", conn, j);
        
        //can be up to 1000
        for (i=0; i<=1000; i++)
        {
            printf("[i] Fuzzing j=%d : ", j);
            printf("[i] i=%d\r\n", i);
            
            //printf("[i] Fuzzing IOConnectMapMemory32 type %d at NULL Page\r\n", i);
            //err = IOConnectMapMemory(conn, i, mach_task_self(), &addr32, &size, NULL);
            //printf("[i] Iteration %d did not cause a crash.\r\n", i);
            
            //printf("[i] Fuzzing IOConnectMapMemory32 type %d with addr32\r\n", i);
            //err = IOConnectMapMemory(conn, i, mach_task_self(), &addr32, &size, kIOMapAnywhere);
            //printf("[i] Iteration %d did not cause a crash.\r\n", i);
            
            //fprintf(fp, "[i] Fuzzing IOConnectMapMemory32 type %d with addr64\r\n", i);
            //err = IOConnectMapMemory(conn, i, mach_task_self(), &addr64, &size, kIOMapAnywhere);
            //fprintf(fp, "[i] Iteration %d did not cause a crash.\r\n", i);
            
            //printf("[i] Fuzzing IOConnectUnmapMemory type %d with addr64\r\n", i);
            //err = IOConnectUnmapMemory(conn, i, mach_task_self(), addr64);
            //printf("[i] Iteration %d did not cause a crash.\r\n", i);
            
            printf("[i] Fuzzing IOConnectMapMemory64 type %d with addr64\r\n", i);
            err = IOConnectMapMemory64(conn, i, mach_task_self(), &addr64, &size, NULL);
            printf("[i] Iteration %d did not cause a crash.\r\n", i);
            
            //printf("[i] Fuzzing IOConnectUnmapMemory type %d with addr32\r\n", i);
            //err = IOConnectUnmapMemory(conn, i, mach_task_self(), addr32);
            //printf("[i] Iteration %d did not cause a crash.\r\n", i);
        } //i for

    }// else

}//j for
    //fclose(fp);
    return 0;
}//main
