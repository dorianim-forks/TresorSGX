#include <linux/module.h>
//#include <linux/init.h>	
//#include <linux/kmod.h>	
#include <linux/kernel.h>	
#include <linux/string.h>	
#include <linux/scatterlist.h>

/* Crypto API */
#include <crypto/skcipher.h>

#define TRESOR_BLOCK_SIZE (16) // in bytes

unsigned char test_plain_text[64] =   {	0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
										0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
										0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
										0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

unsigned char test_key_128[16] =      {	0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

static void printCharAsHex(const unsigned char mem[], unsigned int count)
{
   int i, k = 0;
    char hexbyte[11] = "";
    char hexline[126] = "";
    for (i=0; i<count; i++) { // traverse through mem
    	sprintf(hexbyte, "0x%02X|", mem[i]); // add current byte to hexbyte
        strcat(hexline, hexbyte); // add hexbyte to hexline
        // print line every 16 bytes or if this is the last for loop
        if ((((i)%15 == 0) && (i != 0)) || (i+1==count)) { 
            k++;
            //printf("%d: %s",k , hexline); // print line to console
            //syslog(LOG_INFO, "%d: %s",k , hexline); // print line to syslog
            printk(KERN_INFO "test_tresor_lkm: l%d: %s",k , hexline); // print line to kernellog
            memset(&hexline[0], 0, sizeof(hexline)); // clear array
        }
    }
}

static int test128(struct crypto_skcipher *tfm, unsigned long numBlocks)
{
	unsigned int buffer_size = numBlocks * TRESOR_BLOCK_SIZE;
	unsigned int i;
	unsigned char testVector[sizeof(test_plain_text)] = { 0 };
	unsigned char testResult[sizeof(test_plain_text)] = { 0 };
	struct skcipher_request *req;
	struct scatterlist sg_src;
	struct scatterlist sg_dst;
	int ret;

	if (buffer_size > sizeof(test_plain_text)) {
		printk(KERN_ERR "test_tresor_lkm: requested %u bytes exceeds test vector size %zu\n",
		       buffer_size, sizeof(test_plain_text));
		return -EINVAL;
	}

	printk(KERN_INFO "test_tresor_lkm: buffer_size: %u numBlocks: %lu BLOCK_SIZE: %u\n",
	       buffer_size, numBlocks, TRESOR_BLOCK_SIZE);

	// Init the test vector and the test result
	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	printCharAsHex(testVector, 16);

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	
	printk(KERN_INFO "test_tresor_lkm: Call crypto_skcipher_encrypt ...\n");
	sg_init_one(&sg_src, testVector, buffer_size);
	sg_init_one(&sg_dst, testResult, buffer_size);
	skcipher_request_set_crypt(req, &sg_src, &sg_dst, buffer_size, NULL);
	ret = crypto_skcipher_encrypt(req);
	if (ret) {
		printk(KERN_ERR "test_tresor_lkm: encryption failed: %d\n", ret);
		skcipher_request_free(req);
		return ret;
	}

	printCharAsHex(testResult, 16);

	// decrypt


	printk(KERN_INFO "test_tresor_lkm: Call crypto_skcipher_decrypt ...\n");
	sg_init_one(&sg_src, testResult, buffer_size);
	sg_init_one(&sg_dst, testVector, buffer_size);
	skcipher_request_set_crypt(req, &sg_src, &sg_dst, buffer_size, NULL);
	ret = crypto_skcipher_decrypt(req);
	if (ret) {
		printk(KERN_ERR "test_tresor_lkm: decryption failed: %d\n", ret);
		skcipher_request_free(req);
		return ret;
	}

	skcipher_request_free(req);


	printCharAsHex(testVector, 16);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
		{
			return 1;
		}
	}
	printk(KERN_INFO "test_tresor_lkm: decrypt result verification passed\n");
	return 0;
}

static int __init tresor_test_init( void )
{
	int key_len;
	int ret;
	struct crypto_skcipher *tfm;

	char *cipherName = "ecb(tresorsgx)";
	//char *cipherName = "ecb(aes)";

	printk(KERN_INFO "test_tresor_lkm: Entering: %s\n", __FUNCTION__);

	ret = -EFAULT;


	// run own test vectors
	printk(KERN_INFO "test_tresor_lkm: test tresorsgx tfm");

	tfm = NULL;
	tfm = crypto_alloc_skcipher(cipherName, 0, 0);
	if (tfm == NULL || IS_ERR(tfm)) {
		printk(KERN_ERR "test_tresor_lkm: could not allocate cipher handle for %s\n", cipherName);
		return 0;
	}

	  key_len = TRESOR_BLOCK_SIZE;

  	// set key
	if (crypto_skcipher_setkey(tfm, test_key_128, key_len)) {
		printk(KERN_ERR "test_tresor_lkm: could not set key");
		crypto_free_skcipher(tfm);
		return 0;
	}
	printk(KERN_INFO "test_tresor_lkm: run 1 block(s):  AES-128..\n");

	// test crypto
	ret = test128(tfm, 1);
	if (ret == 0) {
		printk(KERN_INFO "test_tresor_lkm: 1 block(s):  AES-128: PASS\n");
	} else {
		printk(KERN_INFO "test_tresor_lkm: 1 block(s):  AES-128: FAIL: %d\n", ret);
	}

	// free cipher handle
	crypto_free_skcipher(tfm);
	
	
	printk(KERN_INFO "test_tresor_lkm: ended successfully\n");
	return 0;
}
 
static void __exit tresor_test_exit( void )
{
	printk(KERN_INFO "test_tresor_lkm: Entering: %s\n", __FUNCTION__);
}


module_init( tresor_test_init );
module_exit( tresor_test_exit );


MODULE_LICENSE("GPL");
