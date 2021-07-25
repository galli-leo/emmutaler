#ifndef __EVENT_H
#define __EVENT_H

#include <pthread.h>
#include <stdbool.h>

typedef struct event {
    pthread_mutex_t cond_var_lock;
    pthread_cond_t cond_var;
    bool signaled;
} event_t;

/**
 * @brief Initializes the given event.
 * 
 * @param event 
 */
void initialize_event(event_t* event);

void wait_event(event_t* event);
void signal_event(event_t* event);
void reset_event(event_t* event);

#endif /* __EVENT_H */
