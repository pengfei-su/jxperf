#ifndef __WATCHPOINT_STACK__
#define __WATCHPOINT_STACK__

#ifndef MAX_STACK
#define MAX_STACK 128
#endif

typedef struct WatchpointStack {
    int top;
    SampleData_t sd[MAX_STACK];
} WatchpointStack_t; 

static bool isEmptyStack(WatchpointStack_t *wpStack) { 
    return (wpStack->top == -1);
} 

static bool isFullStack(WatchpointStack_t *wpStack) {
    return (wpStack->top == (MAX_STACK - 1)); 
}

static void push(WatchpointStack_t *wpStack, SampleData_t *sampleData) { 
    assert(wpStack->top != MAX_STACK - 1);
    wpStack->sd[++wpStack->top] = *sampleData; 
} 

static void pop(WatchpointStack_t *wpStack, SampleData_t *sampleData) { 
    // assert(wpStack->top != - 1);
    *sampleData = wpStack->sd[wpStack->top--];
} 

static SampleData_t peek(WatchpointStack_t *wpStack) { 
    return wpStack->sd[wpStack->top]; 
} 

#endif 
