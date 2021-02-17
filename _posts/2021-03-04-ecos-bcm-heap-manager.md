---
layout: post
title: Broadcom eCOS | Reversing the Heap Allocator
author: qkaiser
description: Let's reverse Broadcom's custom memory allocator for eCOS.
summary: Let's reverse Broadcom's custom memory allocator for eCOS.
image: /assets/wolfgang_tilmans_by_dbking.jpg
date: 2021-03-04 09:00:00
tags: [ecos, memory, heap, reversing]
---

!["Wolfgang Tillmans" by dbking is licensed under CC BY 2.0]({{site.url}}/assets/wolfgang_tilmans_by_dbking.jpg)

One crucial element of exploiting dynamic memory allocation issues (use-after-free, double-free, heap overflow) is
to have a detailed understanding of how the memory is dynamically allocated by a given system.

All modern systems rely on heap allocators. These allocators use different allocation strategies that differs
based on the developers objectives. Examples include jemalloc in BSD, kalloc in iOS kernel, and glibc's ptmalloc.

eCOS provides a default heap allocator that implements dlmalloc (see [https://doc.ecoscentric.com/ref/memalloc-standard-api.html](https://doc.ecoscentric.com/ref/memalloc-standard-api.html)),
and expose the C standard functions to use it (*malloc*, *calloc*, *realloc*, *free*), on top of C++ *new* and *delete* operators.

Broadcom, for its own reasons, chose not to rely on the default heap allocator and implemented its own allocator named **BcmHeapManager**.

### A Quick Look Into the eCOS Source

If we check the eCOS source code provided by the different manufacturers using the Broadcom eCOS variant (see [research]({{site.url}}/research) for samples), we'll see that this
heap allocator is referenced in a few locations:

- packages/services/memalloc/common/v2_0/src/malloc.cxx
- packages/services/memalloc/common/v2_0/include/membcm.hxx
- packages/services/memalloc/common/v2_0/include/mvarimpl.inl
- packages/net/bsd_tcpip/v2_0/src/ecos/support.c

Prototypes for *malloc* and *free* are defined in *packages/net/bsd_tcpip/v2_0/src/ecos/support.c*:

{% highlight c %}
#if !STATIC_POOL
 void *BcmHeapAlloc( size_t size );
 void BcmHeapFree( void *p );
#endif
{% endhighlight %}

In *packages/services/memalloc/common/v2_0/src/malloc.cxx*, we get the first explanation about how
all of this works in the comment section:

{% highlight c %}
// \/ \/ \/ \/ \/ \/ \/ Broadcom hack \/ \/ \/ \/ \/ \/ \/
#if 0
extern "C"
{
    void *BcmHeapManagerInitFunction(void);
}

// DPullen - Nov 20, 2003 - this hack is done to support Broadcom's HeapManager.
// We like ours for a number of reasons, but we don't force everyone to use it.
// This function returns NULL in the normal case (BRCM HeapManager disabled).
// If BRCM HeapManager is enabled, we will override this function externally
// so that it returns non-NULL, allowing us to take over the heap.
//
// We have hacked mvarimpl.inl (Cyg_Mempool_Variable_Implementation constructor)
// to call this function and do something appropriate based on the result.
void *BcmHeapManagerInitFunction(void)
{
    return 0;
}
#endif // 0
// /\ /\ /\ /\ /\ /\ /\ Broadcom hack /\ /\ /\ /\ /\ /\ /\.
{% endhighlight %}


In *packages/services/memalloc/common/v2_0/include/membcm.hxx*, a shim to use Broadcom memory allocator as system pool handler is defined:

{% highlight c++ %}
class Cyg_Mempool_Broadcom
{
  public:
    // Constructor: gives the base and size of the arena in which memory is
    // to be carved out, note that management structures are taken from the
    // same arena.
    Cyg_Mempool_Broadcom( cyg_uint8 * base, cyg_int32  size, cyg_int32 alignment = 8)
    {
      if (BcmHeapManagerInitFunction() != 0)
      {
        typedef void (*BcmHeapManagerInitCallout)(void *pHeapBegin, unsigned long  heapSizeBytes);

        BcmHeapManagerInitCallout HeapInitCallout = (BcmHeapManagerInitCallout) BcmHeapManagerInitFunction();

        HeapInitCallout( base, size );

        return;
      }
    }
    // Destructor
    ~Cyg_Mempool_Broadcom(){};
//--snip--
{% endhighlight %}

The last piece of the puzzle is present in *packages/services/memalloc/common/v2_0/include/mvarimpl.inl*:

{% highlight c++ %}
// -------------------------------------------------------------------------
// \/ \/ \/ \/ \/ \/ \/ Broadcom hack \/ \/ \/ \/ \/ \/ \/

extern "C"
{
  void *BcmHeapManagerInitFunction(void);
}

// /\ /\ /\ /\ /\ /\ /\ Broadcom hack /\ /\ /\ /\ /\ /\ /\.

inline
Cyg_Mempool_Variable_Implementation::Cyg_Mempool_Variable_Implementation(
         cyg_uint8 *base,
         cyg_int32 size,
         CYG_ADDRWORD align )
{
  CYG_REPORT_FUNCTION();

  CYG_ASSERT( align > 0, "Bad alignment" );
  CYG_ASSERT(0!=align ,"align is zero");
  CYG_ASSERT(0==(align & align-1),"align not a power of 2");

// \/ \/ \/ \/ \/ \/ \/ Broadcom hack \/ \/ \/ \/ \/ \/ \/
#if 0
  // Here is where we make use of the function defined in malloc.cxx (or
  // overridden externally in Broadcom's source code) to determine whether
  // or not the BRCM HeapManager is operational.  If this function returns
  // NULL, the BRCM HeapManager is disabled, and we do normal initialization.
  // If this function returns non-NULL, we call the function and allow the
  // BRCM HeapManager to take over the heap.
  if (BcmHeapManagerInitFunction() != 0)
  {
    typedef void (*BcmHeapManagerInitCallout)(void *pHeapBegin,
                                                   unsigned long heapSizeBytes);

    BcmHeapManagerInitCallout HeapInitCallout = (BcmHeapManagerInitCallout) BcmHeapManagerInitFunction();

    HeapInitCallout(base, size);

    bottom = NULL;

    return;
  }
#endif
// /\ /\ /\ /\ /\ /\ /\ Broadcom hack /\ /\ /\ /\ /\ /\ /\.
{% endhighlight %}

So we know the system uses the BcmHeapManager implementation and that it is linked at compile time. The implementation itself
is closed source so we'll need to manually reverse engineer the dynamic memory management functions (malloc, free, realloc, calloc) from an existing firmware.

Let's start by looking at the structures used to represent allocated memory.

### Reconstructing Heap Nodes Metadata

One way of understanding heap nodes metadata is by looking at dynamic memory of a running system.
In the excerpt below, we list the free list content by using the CLI command 'CM/HeapManager/walk':

{% highlight asm %}
CM/HeapManager> walk

BcmHeapManager - free memory nodes:

NodeAddr    NodeSize  AllocSize   ThreadId
----------  --------  ---------  ----------
0x81b52570  74412536   74412524  0x00000000
0x862ee250    657904     657892  0x00000000
0x863adc7c        16          4  0x00000000
0x863b188c        20          8  0x00000000
0x863b1d28      1860       1848  0x00000000
0x863b24ac        96         84  0x00000000
0x86422934        72         60  0x00000000
0x86422e3c        40         28  0x00000000
0x8642393c      1564       1552  0x00000000
0x86429f38        16          4  0x00000000 <-- node x
0x864e67ec        20          8  0x00000000 <-- node y
0x8653fdb0       112        100  0x00000000 <-- node z
0x866f6cac       524        512  0x00000000
{% endhighlight %}

If we read the content at address *0x864e67ec* (node y), we see that the two first words are
pointers - the first one to the next node (*0x8653fdb0*, node z), the second one to the previous node (*0x86429f38*, node x) - and
the third word is the node size (0x14 = 20).

{% highlight asm %}
CM> read_memory -n 32 0x864e67ec
864e67ec: 8653fdb0  86429f38  00000014  01200cc8 | .S...B.8..... ..
864e67fc: 1676dbf0  86525fc4  863b2650  00000014 | .v...R_..;&P....
{% endhighlight %}

We can repeat the experience with the previous node:

{% highlight asm %}
CM> read_memory -n 32 0x86429f38
86429f38: 864e67ec  8642393c  00000010  00730000 | .Ng..B9<.....s..
86429f48: 863b256c  863adca8  00000038  863adcb4 | .;%l.:.....8.:..
{% endhighlight %}

So we can consider that a heap node looks like this:

{:.foo}
![heap node]({{site.url}}/assets/bcm_heap_node.png)

Which can be define in C like this:

{% highlight c %}
typedef struct heap_node {
  struct heap_node* prev_node;
  struct heap_node* next_node;
  unsigned int node_size;
} heap_node;
{% endhighlight %}
<!-- TODO: insert diagram -->

### BcmHeapManager Allocation Strategy

There are 3 doubly linked lists:
- HEAP\_ALLOC\_LIST - keeps track of allocated memory
- HEAP\_FREE\_LIST - keeps track of available memory
- HEAP\_FREED\_LIST - used during coalescing

During the heap manager initialization, the freed list and alloc list are initialized
as empty lists. The free list is initialized as a list with a single node element the size
of the entire memory pool.

During a device normal operation, the content of these lists can look like the diagram below:

![BCM Heap Structure]({{site.url}}/assets/bcm_ecos_heap_struct.png)

#### BcmHeapManager Data Section Variables

The following variables comes from the data section and are heavily used by the dynamic allocator:

| Name                              | Purpose   |
|-----------------------------------|-----------|
| BCM\_HEAP\_ALLOC\_LIST                 | Allocation list  |
| BCM\_HEAP\_FREE\_LIST                  | Free list  |
| BCM\_HEAP\_FREED\_LIST                 | Freed list  |
| BCM\_HEAP\_INITIALIZED                 | Boolean indicating whether the heap structure has been initialized. Set by BcmHeapInit.  |
| BCM\_HEAP\_INITIAL\_SIZE               | Heap initial size  |
| BCM\_HEAP\_FREE\_MEMORY                | Currently available memory on the heap  |
| BCM\_HEAP\_REGION\_START               | Pointer to the start of the heap  |
| BCM\_HEAP\_REGION\_END                 | Pointer to the end of the heap.  |
| BCM\_HEAP\_REGION\_END\_OVERHEAD       | Pointer to the end of the heap + overhead |
| BCM\_HEAP\_LOW\_WATER                  | Heap low water mark  |
| BCM\_HEAP\_FRAGMENTATION               | Heap fragmentation percentage |
| BCM\_HEAP\_ALLOC\_NODES                | Amount of nodes on the alloc list |
| BCM\_HEAP\_FREE\_NODES                 | Amount of nodes on the free list  |
| BCM\_HEAP\_FREED\_NODES                | Amount of nodes on the freed list  |
| BCM\_HEAP\_ALLOC\_CORRUPTS             | Amount of memory corruptions detected during malloc/realloc  |
| BCM\_HEAP\_BCHECK\_CORRUPTS            | Amount of memory corruptions found during bound checks  |
| BCM\_HEAP\_ALLOC\_FAILS                | Amount of failed allocation |
| BCM\_HEAP\_FREE\_FAILS                 | Amount of failed deallocation  |
| BCM\_HEAP\_ALLOC\_FAILS\_SIZE          | Last fail size |
| BCM\_HEAP\_FREE\_CORRUPTS              | Amount of memory corruptions detected during free/realloc  |
| BCM\_HEAP\_NODE\_CORRUPT\_FATAL        | Corrupted nodes found during bounds check that could not be recovered or fixed |
| BCM\_HEAP\_NODE\_CORRUPT\_RECOV        | Corrupted nodes found during bounds check that could be recovered or fixed |
| BCM\_HEAP\_STATS                       | Heap statistics structure |
| BCM\_HEAP\_NODE\_SIZE                  | Latest allocated node size  |
| BCM\_HEAP\_ALLOC\_TRACE\_ENABLED       | Enable alloc tracing  |
| BCM\_HEAP\_BOUNDS\_CHECK\_ENABLED      | Enable bounds checking on heap  |

**Note**: the `BCM_HEAP` naming convention comes from the presence of two strings in the binary: `BCM_HEAP_BOUNDS_CHECK` and `BCM_HEAP_THREAD_TRACKING`.



#### BcmHeapAlloc

The allocation strategy relies on a [FIFO-ordered first fit](https://www.memorymanagement.org/glossary/f.html#fifo.ordered.first.fit),
where the allocator goes over the free list and carves a node out of the first node with enough memory to contain the newly requested
allocation. The newly created heap node is then inserted at the head of the alloc list.

If the allocator cannot find a suitable candidate before it reaches the end of the free list or after 500 iteration over the list, the
allocation simply fails.

Pretty simple, right ? I re-wrote the implementation in C for reference (see below), note that it's just to give you a general idea.

{% highlight c %}
/**
  * BcmHeapManager malloc() implementation, reversed from a TCG300 firmware.
  *
  * Author: Quentin Kaiser <quentin@ecos.wtf>
  *
  */
#define cyg_handle_t  unsigned int
int cyg_scheduler_lock(void);
int cyg_scheduler_unlock(void);
cyg_handle_t cyg_thread_self(void);

typedef struct heap_node {
  struct heap_node* prev_node;
  struct heap_node* next_node;
  unsigned int node_size;
} heap_node;

typedef struct heap_stat {
  cyg_handle_t thread_handle;
  unsigned int size;
  heap_node* node;
} heap_stat;

typedef struct heap_stats {
  unsigned int counter;
  heap_stat alloc_array[20];
} heap_stats;

void * malloc(long unsigned int size)
{
  unsigned int node_size;
  unsigned int alloc_size;
  cyg_handle_t self_thread;

  heap_node *tmp_node;
  heap_node *candidate_node;

  heap_node *current_node;

  int FREE_STATUS;
  int HEAP_INITIALIZED;
  int HEAP_ALLOC_FAILS;
  int HEAP_ALLOC_FAILS_SIZE;
  int HEAP_FREE_NODES;
  int HEAP_ALLOC_NODES;
  int HEAP_FREE_MEMORY;
  int HEAP_CURRENT_SIZE_LOW_WATER;

  heap_stats* HEAP_STATS;
  heap_node* FREED_LIST;
  heap_node* FREE_LIST;
  heap_node* ALLOC_LIST;


  FREE_STATUS = 0;
  if (HEAP_INITIALIZED == 0) {
    FREE_STATUS = 3;
  }
  else {
    if (size == 0) {
      FREE_STATUS = 0;
      return 0;
    }
    // add 0xc to the requested size to account for metadata
    alloc_size = size + 0xc;

    // if we successfully locked the scheduler
    if (cyg_scheduler_lock() == 1) {

      // init counter
      int counter = 0;

      // if the free list is initialized
      if (FREE_LIST != 0) {
        // set the initial node_size to the size of the free list first node
        node_size = FREE_LIST->node_size;
        // set the current_node
        current_node = FREE_LIST;
        // we loop through the free list until we find an alloca of same size
        while (candidate_node = current_node, node_size != alloc_size) {
          candidate_node = tmp_node;
          
          // if our requested size is lower than the current node_size
          // we use that current_node as candidate
          if ((alloc_size < node_size && (candidate_node = current_node, tmp_node != 0)) &&
              (
               candidate_node = tmp_node, node_size < tmp_node->node_size)) {
            candidate_node = current_node;
          }
          counter++;

          // if we have reached the end of the free list or went over at least 500 candidates,
          // we break out of the loop
          if ((candidate_node != 0 && counter > 500) || (current_node = current_node->prev_node) == 0)
            break;
          node_size = current_node->node_size;
          tmp_node = candidate_node;
        }
      }
      // we could not find a candidate from the free list
      // allocation failed
      if (candidate_node == 0) {
        if (FREE_STATUS == 0) {
          FREE_STATUS = 0xc;
          // increment allocation fails counter
          HEAP_ALLOC_FAILS++;
          // set the last allocation fail size
          HEAP_ALLOC_FAILS_SIZE = size;
        }
      }
      else {
        // if our requested size is less then the size of our candidate node from the free list
        if (alloc_size < candidate_node->node_size) {
          // decrement the size of the candidate element we got from the free list
          unsigned int remaining_size = candidate_node->node_size - alloc_size;
          candidate_node->node_size = remaining_size;
          // create a heap_node for our requested alloca, precisely at the end of the candidate
          // element we got from the free list
          candidate_node = (heap_node *)(candidate_node + remaining_size);
          // set our heap_node size to the requested size
          candidate_node->node_size = alloc_size;
        }
        // otherwise the candidate size and our requested size are equals
        // so we just have to re-chain everything
        else {
          // if it's the first element of the free list, put it into the freed list
          if (candidate_node->prev_node == 0) {
            FREED_LIST = candidate_node->next_node;
          }
          // re-chain in the free list
          else {
            candidate_node->prev_node->next_node = candidate_node->next_node;
          }
          if (candidate_node->next_node != 0) {
            candidate_node->next_node->prev_node = candidate_node->prev_node;
          }
          // decrease total of nodes from free list
          HEAP_FREE_NODES--;
        }
        // decrease available memory
        HEAP_FREE_MEMORY -= candidate_node->node_size;

        // adjust heap size metadata
        if (HEAP_FREE_MEMORY < HEAP_CURRENT_SIZE_LOW_WATER) {
          HEAP_CURRENT_SIZE_LOW_WATER = HEAP_FREE_MEMORY;
        }
        
        // dequeue the element from the free list
        if (FREE_LIST == candidate_node) {
          FREE_LIST = candidate_node->prev_node;
          candidate_node->prev_node = 0;
        }
        else {
          candidate_node->prev_node = 0;
        }

        // queue the element into the alloc list
        candidate_node->next_node = ALLOC_LIST;
        ALLOC_LIST = candidate_node;
        if (candidate_node->next_node != 0) {
          candidate_node->next_node->prev_node = candidate_node;
        }

        // manage statistics
        heap_stat* hstat = (heap_stat*)HEAP_STATS->alloc_array + HEAP_STATS->counter;
        hstat->thread_handle = cyg_thread_self();
        hstat->node = candidate_node;
        hstat->size = size;
        HEAP_STATS->counter++;
        if (HEAP_STATS->counter == 0x14) {
          HEAP_STATS->counter = 0;
        }
        // increment allocation counter
        HEAP_ALLOC_NODES++;
      }
      if (cyg_scheduler_unlock() == 1) {
        return candidate_node + 1;
      }
      FREE_STATUS = 2;
      return candidate_node + 1;
    }
    FREE_STATUS = 1;
  }
  return 0;
}
{% endhighlight %}

#### BcmHeapAlloc Stats Counter

The dynamic memory allocator is always keeping track of the last 20 successful allocation. To do so, 
the code relies on a structure present in the .data section that I called 'heap_stats'. The structure
is provided in C below:

{% highlight c %}
typedef struct heap_stat {
    cyg_handle_t thread_handle;
    unsigned int size;
    heap_node* node;
} heap_stat;

typedef struct heap_stats {
    unsigned int counter;
    heap_stat alloc_array[20];
} heap_stats;
{% endhighlight %}

As we can see in the excerpt below, anytime a successful allocation is made, a *heap_stat* element is placed
into the *alloc_array* array. The *heap_stat* structure holds a reference to the allocating thread, a reference
to the allocated node, and the allocated node size.

{% highlight c %}
//--snip--
// manage statistics
heap_stat* hstat = (heap_stat*)HEAP_STATS->alloc_array + HEAP_STATS->counter;
hstat->thread_handle = cyg_thread_self();
hstat->node = candidate_node;
hstat->size = size;
HEAP_STATS->counter++;
if (HEAP_STATS->counter == 0x14) {
  HEAP_STATS->counter = 0;
}
//--snip--
{% endhighlight %}

In the firmwares I have looked at so far, malloc is the only function referencing this statistics structure. It's probably
used by tracing functions when the feature is enabled via the `BCM_HEAP_ALLOC_TRACE_ENABLED` build flag.


#### BcmHeapFree

Here's the reversed free function:

{% highlight c %}
/**
 * BcmHeapManager free() implementation, reversed from a TCG300 firmware.
 *
 * Author: Quentin Kaiser <quentin@ecos.wtf>
 *
 */
#define cyg_handle_t  unsigned int
int cyg_scheduler_lock(void);
int cyg_scheduler_unlock(void);
cyg_handle_t cyg_thread_self(void);

typedef struct heap_node {
  struct heap_node* prev_node;
  struct heap_node* next_node;
  unsigned int node_size;
} heap_node;

typedef struct heap_stat {
  cyg_handle_t thread_handle;
  unsigned int size;
  heap_node* node;
} heap_stat;

typedef struct heap_stats {
  unsigned int counter;
  heap_stat alloc_array[20];
} heap_stats;

void free(void *ptr)
{
  int counter;
  heap_node *node_a;
  int locked;
  heap_node *freed_head_node;
  heap_node *current_node;
  heap_node *freed_node;

  int FREE_STATUS;
  int HEAP_INITIALIZED;
  int HEAP_ALLOC_FAILS;
  int HEAP_ALLOC_FAILS_SIZE;
  int HEAP_FREE_NODES;
  int HEAP_ALLOC_NODES;
  int HEAP_FREE_MEMORY;
  int HEAP_CURRENT_SIZE_LOW_WATER;

  heap_stats* HEAP_STATS;
  heap_node* FREED_LIST;
  heap_node* FREE_LIST;
  heap_node* ALLOC_LIST;

  FREE_STATUS = 0;
  if (HEAP_INITIALIZED == 0) {
    FREE_STATUS = 3;
  }
  else {
    // setup a heap_node by making it point to ptr - 0xc, which
    // is the beginning of the node metadata
    freed_node = (heap_node *)(ptr - 0xc);

    // retrieve the current status
    if (ptr != 0) {
      FREE_STATUS = 1;

      // if locking the scheduler was successful
      if (cyg_scheduler_lock() == 1) {

        // dequeue the node from the alloc list
        if (freed_node->prev_node == 0) {
          ALLOC_LIST = freed_node->next_node;
        }
        else {
          freed_node->prev_node->next_node = freed_node->next_node;
        }
        if (freed_node->next_node != 0) {
          freed_node->next_node->prev_node = freed_node->prev_node;
        }
        // end dequeue from the alloc list

        // edit heap global metadata
        HEAP_FREE_MEMORY += freed_node->node_size;
        HEAP_ALLOC_NODES--;
        HEAP_FREE_NODES++;

        // null node metadata
        freed_node->next_node = 0;
        freed_node->prev_node = 0;

        // coalescing starts here

        current_node = FREED_LIST;
        node_a = freed_node;
        if (FREED_LIST != 0) {
          do {
            // if the freed node allocated memory is lower
            // than the current node allocated memory
            if (freed_node < current_node) {
              // queue the element into the freed list 
              freed_node->prev_node = current_node->prev_node;
              current_node->prev_node = freed_node;
              freed_node->next_node = current_node;
              // NOTE: required ?
              current_node = freed_node;
              if (freed_node->prev_node != 0) {
                freed_node->prev_node->next_node = freed_node;
                // NOTE: required ?
                current_node = FREED_LIST;
              }

              FREED_LIST = current_node;
              current_node = freed_node->prev_node;
              counter = 0;

              // two rounds of coalescing
              do {
                // if two blocks are next to each other in memory
                if ((current_node != 0) && (freed_node != 0) &&
                    ((heap_node *)(&current_node->next_node + current_node->node_size) == freed_node)) {
                
                  // set the size to coalesced size
                  current_node->node_size = current_node->node_size + freed_node->node_size;
                  // chain elements properly in the list
                  current_node->next_node = freed_node->next_node;
                  if (freed_node->next_node != 0) {
                    freed_node->next_node->prev_node = current_node;
                  }
                  else {
                    FREE_LIST = current_node;
                  }
                  // decrement free nodes amount given me merged two into one
                  HEAP_FREE_NODES--;
                  freed_node = current_node;
                }
                if (counter == 0) {
                  freed_node = freed_node->next_node;
                  current_node = freed_node;
                }
                counter++;
              } while (counter < 2);
            }
          } while ((current_node = current_node->next_node) != 0);
          current_node->next_node = freed_node;

          // remove next node
          freed_node->next_node = 0;
          // set previous node to 
          freed_node->prev_node = current_node;

          // set the status
          FREE_STATUS = 2;

          // unlock the scheduler
          if (cyg_scheduler_unlock() == 1) {
            return;
          }
        }
      }
    }
    return;
  }
}
{% endhighlight %}

# Conclusion

Over the course of this article we identified that the Broadcom variant of eCOS uses its own dynamic memory allocator named BcmHeapManager. We then relied on a mix of static and dynamic analysis to understand the backing structures and strategies implemented by this custom allocator (allocation, freeing, coalescing).

With this newly acquired knowledge, we can start investigating how we can gain exploitation primitives by abusing dynamic memory allocation issues (use-after-free, double-free, heap overflow). This will be the subject of its own dedicated article.

As always, if you have any questions, feel free to get in touch via [email](mailto:quentin@ecos.wtf) or [Twitter](https://twitter.com/qkaiser).
