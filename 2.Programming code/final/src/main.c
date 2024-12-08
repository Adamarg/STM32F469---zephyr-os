#include <zephyr.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/sensor.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypto/crypto.h>
#include <crypto/hash.h>



#define STACK_SIZE (2048) // <-- the size of the stack for each thread
#define MAIL_LEN 64 	  // <-- the max length that a mail can have
#define CRYPTO_DRV_NAME CONFIG_CRYPTO_MBEDTLS_SHIM_DRV_NAME // <-- driver name

#define HASH_SIZE 32 // <-- the size of the hash 
#define LOG_HASH 0	 // <-- This log allows to user to see the hash that is been generated.
#define LOG 0

#define CMD_REQ_MALLOC 1 // <-- Malloc request from thread_a to thread_b
#define CMD_MALLOC_PTR 2 // <-- Malloc pointer from thread_b to thread_a
#define CMD_DATA_READY 3 // <-- Data alert from thread_b to thread_a

static K_THREAD_STACK_DEFINE(ta_stack, STACK_SIZE); // <-- thread_a stack
static K_THREAD_STACK_DEFINE(tb_stack, STACK_SIZE); // <-- thread_b stack

static struct k_mbox exchange_mbox; // <-- here the mailbox is set
struct k_thread ta, tb; 		    // <-- here the thread names are set

void thread_a(void *, void *, void *); // <-- function of thread_a
void thread_b(void *, void *, void *); // <-- function of thread_b

// The unsiged integer_7 is created so there will be 1 kb of integers (128 integers)
// In that way every time that the buffer reaches the maximum, the values will be written
// at the begging of the buffer. 

struct uint7 
{
	unsigned int u7 : 7;
};

uint32_t hash_start = 0;
uint32_t hash_end = 0;

void main(void)
{
	static k_tid_t ta_tid, tb_tid; // <-- thread_id
	k_mbox_init(&exchange_mbox);   // <-- initialize of mailbox

	// Here are the parameters the k_thread_create need for the thread creation !!
	// k_tid_t k_thread_create(struct k_thread * new_thread, k_thread_stack_t * stack, size_t stack_size,
	// k_thread_entry_t entry, void * p1, void * p2, void * p3, int prio, uint32_t options, k_timeout_t delay)

	// here the receiver thread is created !!
	tb_tid = k_thread_create(&tb, tb_stack, STACK_SIZE, thread_b, &exchange_mbox, NULL,
				    NULL, -1, K_INHERIT_PERMS, K_NO_WAIT);

	// here the sender thread is created !!
	ta_tid = k_thread_create(&ta, ta_stack, STACK_SIZE, thread_a, &exchange_mbox, NULL,
				    NULL, -1, K_INHERIT_PERMS, K_NO_WAIT);

	while (1) 
	{
		//....//
	}
}


// The hash function is responsible for calculating ,the hash from the given parameters.
void hash(uint8_t * hash_in, uint8_t * hash_out, uint16_t size)
{
	struct device *dev;  // <-- Runtime device structure
	struct hash_ctx ctx; // <-- Pointer to the context structure
	struct hash_pkt pkt; // <-- Structure encoding IO parameters of a hash operation

	ctx.flags = CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS;
	dev = device_get_binding(CRYPTO_DRV_NAME);

	hash_begin_session(dev, &ctx, CRYPTO_HASH_ALGO_SHA256); //<-- the hash session starts here

	pkt.in_buf = hash_in;   // <-- buffer as input to create the hash
	pkt.out_buf = hash_out; // <--  buffer as output the hash result
	pkt.in_len = size;      // <-- the length of the hash_in buffer

	hash_compute(&ctx, &pkt); // <-- Perform a cryptographic hash function	

	hash_free_session(dev, &ctx); // <-- the hash session stops here

	#if LOG_HASH == 1
		printk("Hash: ");
		for (int i = 0; i < 32; i++) //<-- this loop will print the hash
		{
			printk("%02X ", hash_out[i]);
		}
		printk("\r\n");
	#endif
}


// The send function is called from the theads when a mailbox needs to be send.
// Here is where the hash function is called to generate the hash before sending the mail.
void send(struct k_mbox *mbox, uint8_t *id, uint8_t command, uint8_t *data, uint16_t size)
{
	struct k_mbox_msg mmsg; //<-- the message that will be send will be stored here

	uint8_t txdata[MAIL_LEN];          // <-- the data of the message
	uint8_t hash_in[MAIL_LEN] = { 0 }; // <-- Hash input
	uint8_t hash_out[32] = { 0 }; 	   // <-- Hash output

	memcpy(hash_in, id, 4);			   // <-- store the id into hash_in
	memcpy((hash_in + 4), data, size); // <-- store the data after the id

	//hash_start = k_uptime_get_32();
	hash(hash_in, hash_out, (size + sizeof(id))); // <-- call of local hash function for hash compute
	//hash_end = k_uptime_get_32();

	memcpy(txdata, hash_out, HASH_SIZE);	  // <-- store the hash_out into txdata
	memcpy((txdata + HASH_SIZE), data, size); // <-- store the data after the hash_out into the txdata

	mmsg.info = command; 			// <-- message request type
	mmsg.size = (HASH_SIZE + size); // <-- the size of the mail
	mmsg.tx_data = txdata; 			// <-- data to be send
	mmsg.tx_target_thread = K_ANY;  // <-- the destination thread

	k_mbox_put(mbox, &mmsg, K_MSEC(1000)); // <-- this function puts the mail in a queue
}


// The receive function is called from the threads when a mailbox needs to be read.
// Here is where the hash function is called to generate the hash so ,
// there will be checked if there are any changes on the received hash.
void receive(struct k_mbox *mbox, uint8_t *sender_id, uint8_t *data, uint16_t size, uint8_t *command)
{
	struct k_mbox_msg mmsg = { 0 };	// <-- here the message will be stored

	uint8_t rxdata[MAIL_LEN];			 // <-- data to be recieved
	uint8_t hash_in[MAIL_LEN] = { 0 };   // <-- Hash input
	uint8_t hash_out[HASH_SIZE] = { 0 }; // <-- Hash output

	mmsg.size = HASH_SIZE + size;  // <-- sizeof(rxdata)
	mmsg.rx_source_thread = K_ANY; // <-- the source thread

	k_mbox_get(mbox, &mmsg, rxdata,  K_MSEC(1000)); // <-- this function gets the mail from the queue

	*command = mmsg.info;  // <-- here is the command option that says if there is a new malloc or data to be read.

	if(mmsg.info != 0)
	{
		memcpy(hash_in, sender_id, 4);						// <-- store the sender_id into hash_in
		memcpy((hash_in + 4), (rxdata + HASH_SIZE), size);  // <-- store the mailbox data at after the id

		hash(hash_in, hash_out, (size + sizeof(sender_id)));// <-- call of local hash function for hash compute

		if(memcmp(rxdata, hash_out, HASH_SIZE) == 0)  // if the input hash is the same as the local hash then the sender is valid.
		{
			memcpy(data, (rxdata + HASH_SIZE), size);
		}
		else
		{
			printk("Data invalid, aborting...\r\n");
		}
	}

}


// The thread_a is responsible to request the size of the memory (malloc) and to display the values that thread_b takes.
void thread_a(void *p1, void *p2, void *p3)
{
	static struct k_mbox_msg mmsg;      // <-- mailbox message
	static uint16_t malloc_size = 1024; // <-- 1KB of memmory
	static uint8_t txdata[MAIL_LEN];    // <-- the data for transmition
    static uint8_t rxdata[MAIL_LEN];    // <-- the data for recieption
	
	struct sensor_value *mem;           // <-- pointer for malloc
    struct k_mbox *mbox = (struct k_mbox *)p1; // <-- this a local mailbox
	
	int i = 0;

	struct uint7 head = { 0 };		   // <-- the head of the 10 pack on each receive 
	struct uint7 read_counter = { 0 }; // <-- the counter that indicates the memory cell , from 0 - 127

	uint32_t malloc_pointer = 0; // <-- setting the malloc pointer

	uint8_t command = 0; // <-- setting the command

	// setting the mail for transmission
	txdata[0] = malloc_size >> 8;
	txdata[1] = malloc_size;

	uint8_t id[4] = {0xBA, 0xAD, 0xBE, 0xEF};        // <-- the id of thread_a
	uint8_t sender_id[4] = {0xCA, 0xFE, 0x12, 0x34}; // <-- the id of thread_b
	
	send(mbox, id, CMD_REQ_MALLOC, txdata, sizeof(malloc_size)); //<-- sending the malloc size to thread_b

	receive(mbox, sender_id, rxdata, 4, &command); // <-- the pointer of malloc from thread_b

	//Here the malloc pointer is shifted because it is send as an unsighed_integer_32 and not as a pointer.
	malloc_pointer = rxdata[0]; 
	malloc_pointer = malloc_pointer | (rxdata[1] << 8);
	malloc_pointer = malloc_pointer | (rxdata[2] << 16);
	malloc_pointer = malloc_pointer | (rxdata[3] << 24);
    
	mem = (struct sensor_value *) malloc_pointer; // <-- after the shifting it is needed to cast the interger as a pointer to memory 

#if LOG == 1
	printk("Received pointer 0x%p\r\n",mem);
#endif

	k_sleep(K_MSEC(1500));

	//In this while loop , it is cheacked if a new data pack has arrived.
	//If there is then it will be displayed on terminal
	//After the display the command becomes zero again
	while(1)
	{
		receive(mbox, sender_id, rxdata, 1, &command);

		//printk("after receive: %d \r\n",k_uptime_get_32());

		if(command == CMD_DATA_READY)
		{
			head.u7 = rxdata[0];
			
			for(i = 0; i < 10; i++)
			{
				read_counter.u7 = i + head.u7;
				printk("Index: %d, Temp: %d.%06d \r\n",read_counter.u7, mem[read_counter.u7].val1, mem[read_counter.u7].val2);
			}
			// printk("%d \r\n\n",k_uptime_get_32());
			command = 0;
		}
	}
}


// The thread_b is responsible to reserve the memory (malloc) that thread_a requests' and to inform it every 10 new tempreture entries.
void thread_b(void *p1, void *p2, void *p3)
{
	const struct device *dev1 = device_get_binding(DT_LABEL(DT_INST(0, bosch_bme680))); // <-- getting the devide label (bosch -- bme680) 
	struct sensor_value temp;        // <-- Tempreture from BME680
	struct device *dev;              // <-- Runtime device structure
	struct hash_ctx ctx;             // <-- Pointer to the context structure
	struct hash_pkt pkt;             // <-- Structure encoding IO parameters of a hash operation
	static struct k_mbox_msg mmsg;   // <-- mailbox message
	struct sensor_value *mem;        // <-- pointer for malloc
	static uint8_t rxdata[MAIL_LEN]; // <-- data to receive
	static uint8_t txdata[MAIL_LEN]; // <-- data to transmit
	static uint16_t malloc_size = 0; // <-- set as zero on reciever

	uint32_t sensor_read_start = 0;
	uint32_t sensor_read_end = 0;

	uint32_t send_start = 0;
	uint32_t send_end = 0;

	int i = 0;

	uint32_t malloc_pointer = 0; // <-- setting the malloc pointer

	uint8_t command = 0;

	uint8_t id[4] = {0xCA, 0xFE, 0x12, 0x34};        // <-- the id of thread_b
	uint8_t sender_id[4] = {0xBA, 0xAD, 0xBE, 0xEF}; // <-- the id of thread_a

	struct k_mbox *mbox = (struct k_mbox *)p1; // <-- this a local mailbox

	// The uint_7 is created so there will be 1 kb of integers (128 integers)
	// In that way every time that the buffer reaches the maximum, the values will be written
	// at the begging of the buffer. 
	struct uint7 head = {0};
	struct uint7 tail = {0};

	receive(mbox, sender_id, rxdata, 2, &command);  // <-- this mailbox contains the malloc size

	printk("Received data: %02X %02X\r\n", rxdata[0], rxdata[1]);

	malloc_size = (rxdata[1] << 8) | rxdata[0]; //<-- get the size for malloc

	if(malloc_size > 0)
	{
		mem = (struct sensor_value *)k_malloc(malloc_size); //<-- malloc 1KB for this example
		printk("malloc pointer --> %p\r\n", mem); //<-- print malloc pointer

		malloc_pointer = mem; //<-- here the pointer is stored as an unsighed_32bit_integer
		
		//Here the malloc pointer is shifted because it is send as an unsighed_integer_32 and not as a pointer.
		txdata[0] = malloc_pointer;
		txdata[1] = (malloc_pointer >> 8); 
		txdata[2] = (malloc_pointer >> 16); 
		txdata[3] = (malloc_pointer >> 24); 

		send(mbox, id, CMD_MALLOC_PTR, txdata, sizeof(malloc_pointer));//<-- the mailbox contains the pointer of the malloc
	}

	// In this while the tempe values are read and stored in packes of 10.
	// There is a delay because the read is to fast. In that was there will be diferent values. 
	while(1)
	{

	    //printk("before store : %d \r\n",k_uptime_get_32());
		// sensor_read_start = k_uptime_get_32();
		//sensor_read_start = k_cycle_get_32();

		for(i = 0; i < 10; i++)
		{
			sensor_sample_fetch(dev1);
			sensor_channel_get(dev1, SENSOR_CHAN_AMBIENT_TEMP, &temp);
			mem[tail.u7].val1 = temp.val1 - 6; //<-- the int part of the temp (-6 deg for calibration)
			mem[tail.u7].val2 = temp.val2;//<-- the float part of the temp

			tail.u7++;

			//k_sleep(K_MSEC(200));
		}

		// sensor_read_end = k_uptime_get_32();	
		//sensor_read_end = k_cycle_get_32();

		//printk("after store: %d \r\n",k_uptime_get_32());

		txdata[0] = head.u7;

		//send_start = k_uptime_get_32();
		send(mbox, id, CMD_DATA_READY, txdata, 1); //<-- A pack of 10 integers is been send to thread_a
		//send_end = k_uptime_get_32();

		head.u7 = tail.u7;

		//printk("%d,%d,%d\r\n", (sensor_read_end - sensor_read_start), (send_end - send_start), (hash_end - hash_start));

		//printk("after send: %d \r\n",k_uptime_get_32());
	
	}
}