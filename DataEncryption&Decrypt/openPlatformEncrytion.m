//
//  BLEncrytion.m
//  blecenter
//
//  Created by hancc on 6/6/16.
//  Copyright © 2016 com.het. All rights reserved.
//

#import "openPlatformEncrytion.h"

@interface openPlatformEncrytion()

@end




@implementation openPlatformEncrytion
{
    CCCryptorRef encryptor;
    CCCryptorRef dencryptor;
}

// convert a hex NSString to NSData, spaces and angled brackets are ignored
- (NSMutableData *)dataFromHexString:(NSString *)string
{
    string = [string lowercaseString];
    string = [string stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSMutableData *data= [NSMutableData new];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i = 0;
    int length = (int) string.length;
    while (i < length-1) {
        char c = [string characterAtIndex:i++];
        if (c < '0' || (c > '9' && c < 'a') || c > 'f')
            continue;
        byte_chars[0] = c;
        byte_chars[1] = [string characterAtIndex:i++];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}


-(NSData *)generateKey:(NSString *)macString
{
    if (self.encryptType == Encryption_None) {
        return nil;
    }
    
    NSAssert(macString.length==12 ,@"mac adress must be 12 bytes");
 
    NSData *mac = [self dataFromHexString:macString];
    NSData *randomData = [[self class] randomDataWithLength:16];
     char ekey[16] = {0};
    [randomData getBytes:ekey length:16];
    self.enkey = [NSData dataWithBytes:ekey length:16];
    
    NSData* key =[self generateCipherKey:(UInt8*)mac.bytes random:(UInt8*)randomData.bytes randomLength:(UInt32)randomData.length];
    
    return key;
}

-(NSData *)decryption:(NSData*)data
{
    if (self.encryptType == Encryption_None) {
        return data;
    }
    
    if (data.length%16) {
        return nil;
    }
    return [self AES_ECBWithOperation:kCCDecrypt andKey:self.enkey andInput:data];
}

-(NSData *)encryption:(NSData*)data
{
    if (self.encryptType == Encryption_None) {
        return data;
    }
    if (self.encryptType == AES_ECB128) {
        NSAssert(!(data.length%16),@"encryption data must be align with 16 byte");
    }
   
    //对齐16位
//    NSMutableData *mdata =[NSMutableData dataWithData:data];
//    UInt8 temp[16]={0};
//    if (data.length%16) {
//        [mdata appendBytes:temp length:16-data.length%16];
//    }

//    NSData *endata = [self AES_ECBWithOperation:kCCEncrypt andKey:self.enkey andInput:mdata];
      NSData *endata = [self AES_ECBWithOperation:kCCEncrypt andKey:self.enkey andInput:data];
    
//    NSLog(@"未加密数据src->%@",data);
//    NSLog(@"已加密数据des->%@",endata);
    
    return endata;
}

+(openPlatformEncrytion*)getShareEncryptor
{
    static dispatch_once_t onceToken;
    static openPlatformEncrytion *en;
    dispatch_once(&onceToken, ^{
        en = [[openPlatformEncrytion alloc] init];
        en.encryptType = Encryption_None;
    });
    
    return en;
}


/****************************************************************************************************************************************/
-(void) insertSort:(UInt8 *)arr len:(UInt8) n      // 从大到小排列
{
    int i,j,target;
    
    for(i=1;i<n;i++)
    {
        target =arr[i];             //key为要插入的元素
        
        for(j=i;j>0 && arr[j-1]<target ;j--)
        {
            arr[j] = arr[j-1];     //移动元素的位置.供要插入元素使用
        }
        arr[j] = target ;           //插入需要插入的元素
    }
}



-(UInt8)rc4_skip:(const UInt8 *)key
         keyLen:( UInt32) keylen
           skip:( UInt32) skip
           data:(UInt8 *)data
        dataLen:( UInt32) data_len
{
    
#define S_SWAP(a,b) do { UInt8 t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
    UInt32 i, j, k;
     UInt8 S[256], *pos;
    UInt32 kpos;
    /* Setup RC4 state */
    for (i = 0; i < 256; i++)
    {
        S[i] = i;
    }
    j = 0;
    kpos = 0;
    for (i = 0; i < 256; i++)
    {
        j = (j + S[i] + key[kpos]) & 0xff;
        kpos++;
        if (kpos >= keylen)
        {
            kpos = 0;
        }

        S_SWAP(i,j);
    }
    /* Skip the start of the stream */
    i = j = 0;
    for (k = 0; k < skip; k++)
    {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;

         S_SWAP(i,j);

    }
    /* Apply RC4 to data */
    pos = data;
    for (k = 0; k < data_len; k++)
    {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;

         S_SWAP(i,j);
        *pos++ ^= S[(S[i] + S[j]) & 0xff];
    }
    
    return 0;
}

-(NSData*)generateCipherKey:(UInt8 *)ptrMac
                  random: (UInt8*) ptrRandom
                 randomLength:(UInt32)randomLen

{
    UInt8 index;
    UInt8 tempbuf[70]={0};
    memcpy(tempbuf, ptrMac, 6);
    for(index=0;index<6;index++)
    {
        tempbuf[index]>>=2;
    }
    
    [self insertSort:tempbuf len:sizeof(tempbuf)];
    [self rc4_skip:tempbuf keyLen:16 skip:0 data:ptrRandom dataLen:randomLen];

    return  [NSData dataWithBytes:&ptrRandom[0] length:16];
}


/****************************************************************************************************************************************/
#pragma mark-- commoncryptor
extern int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes) __attribute__((weak_import));

+ (NSData *)randomDataWithLength:(size_t)length
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result=0;
    if (SecRandomCopyBytes != NULL) {
        result = SecRandomCopyBytes(NULL, length, data.mutableBytes);
    }
    else {
       
    }
    NSAssert(result == 0, @"Unable to generate random bytes: %d", errno);
    
    return data;
}

+ (NSData *)RC4WithOperation:(CCOperation)operation andKey:(NSData *)keyData andInput:(NSData *)inputData
{
    const char *key = [keyData bytes];
    CCCryptorRef cryptor;
    CCCryptorCreateWithMode(operation, kCCModeECB, kCCAlgorithmRC4, ccNoPadding, NULL, key, [keyData length], NULL, 0, 0, 0, &cryptor);
    
    NSUInteger inputLength = inputData.length;
    char *outData = malloc(inputLength);
    memset(outData, 0, inputLength);
    size_t outLength = 0;
    
    CCCryptorUpdate(cryptor, inputData.bytes, inputLength, outData, inputLength, &outLength);
    
    NSData *data = [NSData dataWithBytes: outData length: outLength];
    
    CCCryptorRelease(cryptor);
    free(outData);
    
    return data;

}

- (NSData *)AES_ECBWithOperation:(CCOperation)operation andKey:(NSData *)key andInput:(NSData *)inputData
{
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = kCCSuccess;
    CCCryptorStatus  *error = NULL;

    NSMutableData * keyData;
    keyData = (NSMutableData *) [key mutableCopy];
    

   status = CCCryptorCreateWithMode(operation, kCCModeECB, kCCAlgorithmAES, ccNoPadding, NULL, keyData.bytes, [keyData length], NULL, 0, 0, 0, &cryptor);
    
    if ( status != kCCSuccess )
    {
        if ( error != NULL )
            *error = status;
        return ( nil );
    }
    
    NSData * result = [self _runCryptor: cryptor data:inputData  result: &status];
    if ( (result == nil) && (error != NULL) )
        *error = status;
    
    CCCryptorRelease( cryptor );
    
    return ( result );

}

- (NSData *) _runCryptor: (CCCryptorRef) cryptor data:(NSData *)inputData  result: (CCCryptorStatus *) status
{
    size_t bufsize = CCCryptorGetOutputLength( cryptor, (size_t)[inputData length], true );
    void * buf = malloc( bufsize );
    size_t bufused = 0;
    size_t bytesTotal = 0;
    *status = CCCryptorUpdate( cryptor, [inputData bytes], (size_t)[inputData length],buf, bufsize, &bufused );
    if ( *status != kCCSuccess )
    {
        free( buf );
        return ( nil );
    }
    
    bytesTotal += bufused;
    
    // From Brent Royal-Gordon (Twitter: architechies):
    //  Need to update buf ptr past used bytes when calling CCCryptorFinal()
    *status = CCCryptorFinal( cryptor, buf + bufused, bufsize - bufused, &bufused );
    if ( *status != kCCSuccess )
    {
        free( buf );
        return ( nil );
    }
    
    bytesTotal += bufused;
    
    return ( [NSData dataWithBytesNoCopy: buf length: bytesTotal] );
}

@end
