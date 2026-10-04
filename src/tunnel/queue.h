#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct queue_node {
  void *data;
  struct queue_node *next;
};

struct queue {
  struct queue_node *front;
  struct queue_node *rear;
  size_t size;
  pthread_mutex_t mutex;
  int efd;
};

struct queue *queue_new(void);
void queue_free(struct queue *q);

bool queue_push(struct queue *q, void *item);
bool queue_pop(struct queue *q, void **out_item);

int queue_get_eventfd(const struct queue *q);
bool queue_is_empty(struct queue *q);
size_t queue_size(struct queue *q);
