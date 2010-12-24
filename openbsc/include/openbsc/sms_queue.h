#ifndef SMS_QUEUE_H
#define SMS_QUEUE_H

struct gsm_network;
struct gsm_sms_queue;

int sms_queue_start(struct gsm_network *, int in_flight);
int sms_queue_trigger(struct gsm_sms_queue *);

#endif
