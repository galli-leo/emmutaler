#include "event.h"
#include <pthread.h>

static const pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static const pthread_cond_t init_cond_var = PTHREAD_COND_INITIALIZER;

void initialize_event(event_t *event)
{
    // event->cond_var_lock = init_lock;
    // event->cond_var = init_cond_var;
    pthread_mutex_init(&event->cond_var_lock, NULL);
    pthread_cond_init(&event->cond_var, NULL);
    event->signaled = false;
}

void wait_event(event_t *event)
{
    pthread_mutex_lock(&event->cond_var_lock);
    while (!event->signaled)
        pthread_cond_wait(&event->cond_var, &event->cond_var_lock);

    // event->signaled = false;
    pthread_mutex_unlock(&event->cond_var_lock);
}

void signal_event(event_t *event)
{
    pthread_mutex_lock(&event->cond_var_lock);

    event->signaled = true;

    pthread_cond_signal(&event->cond_var);

    pthread_mutex_unlock(&event->cond_var_lock);
}

void reset_event(event_t *event)
{
    pthread_mutex_lock(&event->cond_var_lock);

    event->signaled = false;

    // should we signal?
    //pthread_cond_signal(&event->cond_var);

    pthread_mutex_unlock(&event->cond_var_lock);
}