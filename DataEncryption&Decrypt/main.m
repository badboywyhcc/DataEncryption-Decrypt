//
//  main.m
//  DataEncryption&Decrypt
//
//  Created by hcc on 2017/3/23.
//  Copyright © 2017年 Hancc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "openPlatformEncrytion.h"


int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        openPlatformEncrytion *manger = [openPlatformEncrytion getShareEncryptor];
        manger.encryptType = AES_ECB128;
        
        
        Byte dataBytes[] = {0x00,0x01,0x02,0x03,0x04,0x05};
        NSData *srcData = [NSData dataWithBytes:dataBytes length:sizeof(dataBytes)];
        
        
        // 不满16位,不满16字节对齐
        NSMutableData *mdata =[NSMutableData dataWithData:srcData];
        UInt8 temp[16]={0};
        if (srcData.length%16)
        {
            [mdata appendBytes:temp length:16-srcData.length%16];
        }

        manger.enkey =[manger generateKey:@"D5F835A5C9AC"];
        
        NSLog(@"\n\r原始数据%@",mdata);
        
        NSData *encrytionData = [manger encryption:mdata];
        NSLog(@"加密数据%@",encrytionData);
        
        NSData *decryptData = [manger decryption:encrytionData];
        NSLog(@"解密数据%@",decryptData);
        NSLog(@"\n\r原始数据%@",mdata);
        
        NSData *encrytionData1 = [manger encryption:mdata];
        NSLog(@"加密数据%@",encrytionData1);
        
        NSData *decryptData1 = [manger decryption:encrytionData];
        NSLog(@"解密数据%@",decryptData1);
    }
    return 0;
}

