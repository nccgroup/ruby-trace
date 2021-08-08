/*
Copyright (c) 2021 NCC Group Security Services, Inc. All rights reserved.
Copyright (C) 1993-2020 Yukihiro Matsumoto. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

module.exports = function(vm) {
let code = `
#include <stddef.h>
#include <stdint.h>

typedef size_t VALUE;
typedef size_t ID;

typedef struct rb_method_cfunc_struct {
  VALUE (*func)();
  VALUE (*invoker)(VALUE recv, int argc, const VALUE *argv, VALUE (*func)());
  int argc;
} rb_method_cfunc_t;

typedef enum {
  VM_METHOD_TYPE_ISEQ,
  VM_METHOD_TYPE_CFUNC,
  VM_METHOD_TYPE_ATTRSET,
  VM_METHOD_TYPE_IVAR,
  VM_METHOD_TYPE_BMETHOD,
  VM_METHOD_TYPE_ZSUPER,
  VM_METHOD_TYPE_ALIAS,
  VM_METHOD_TYPE_UNDEF,
  VM_METHOD_TYPE_NOTIMPLEMENTED,
  VM_METHOD_TYPE_OPTIMIZED,
  VM_METHOD_TYPE_MISSING,
  VM_METHOD_TYPE_REFINED,
} rb_method_type_t;

struct rb_method_definition_struct {
  rb_method_type_t type : 4;
  int alias_count : 28;
  int complemented_count : 28;

  union {
      //rb_method_iseq_t iseq;
      rb_method_cfunc_t cfunc;
      //rb_method_attr_t attr;
      //rb_method_alias_t alias;
      //rb_method_refined_t refined;
      //rb_method_bmethod_t bmethod;
      //enum method_optimized_type optimize_type;
  } body;

  ID original_id;
  uintptr_t method_serial;
};

typedef struct rb_callable_method_entry_struct {
  VALUE flags;
  const VALUE defined_class;
  struct rb_method_definition_struct * const def;
  ID called_id;
  const VALUE owner;
} rb_callable_method_entry_t;


struct rb_call_info {
  ID mid;
  unsigned int flag;
  int orig_argc;
};

typedef size_t rb_serial_t;
#define CACHELINE 64
enum method_missing_reason {
  MISSING_NOENTRY   = 0x00,
  MISSING_PRIVATE   = 0x01,
  MISSING_PROTECTED = 0x02,
  MISSING_FCALL     = 0x04,
  MISSING_VCALL     = 0x08,
  MISSING_SUPER     = 0x10,
  MISSING_MISSING   = 0x20,
  MISSING_NONE      = 0x40
};

struct rb_call_data;

struct rb_call_cache {
  rb_serial_t method_state;
  rb_serial_t class_serial[
      (CACHELINE
       - sizeof(rb_serial_t)
       - sizeof(struct rb_callable_method_entry_struct *)
       - sizeof(uintptr_t)
       - sizeof(enum method_missing_reason)
       - sizeof(VALUE (*)(
             /*struct rb_execution_context_struct*/void *e,
             /*struct rb_control_frame_struct*/void *,
             /*struct rb_calling_info*/void *,
             /*const struct rb_call_data*/void *)))
      / sizeof(rb_serial_t)
  ];

  const struct rb_callable_method_entry_struct *me;
  uintptr_t method_serial; /* me->def->method_serial */

  VALUE (*call)(/*struct rb_execution_context_struct*/void *ec,
                /*struct rb_control_frame_struct*/void *cfp,
                /*struct rb_calling_info*/void *calling,
                /*struct rb_call_data*/void *cd);

  union {
      unsigned int index;
      enum method_missing_reason method_missing_reason;
  } aux;
};

struct rb_call_data {
  struct rb_call_cache cc;
  struct rb_call_info ci;
};

struct rb_call_info_kw_arg {
  int keyword_len;
  VALUE keywords[1];
};

struct rb_call_info_with_kwarg {
  struct rb_call_info ci;
  struct rb_call_info_kw_arg *kw_arg;
};

struct rb_calling_info {
  VALUE block_handler;
  VALUE recv;
  int argc;
  int kw_splat;
};

////

VALUE rb_calling_info__recv(struct rb_calling_info* calling) {
  return calling->recv;
}

int rb_calling_info__argc(struct rb_calling_info* calling) {
  return calling->argc;
}

struct rb_call_cache* rb_call_data__cc(struct rb_call_data* cd) {
  return &cd->cc;
}

struct rb_call_info* rb_call_data__ci(struct rb_call_data* cd) {
  return &cd->ci;
}

struct /*RUBY_ALIGNAS(SIZEOF_VALUE)*/ RBasic {
  VALUE flags;
  const VALUE klass;
};

struct RClass {
  struct RBasic basic;
  VALUE super;
  /*rb_classext_t*/void *ptr;
// #if SIZEOF_SERIAL_T == SIZEOF_VALUE
  /* Class serial is as wide as VALUE.  Place it here. */
  rb_serial_t class_serial;
// #else
//   /* Class serial does not fit into struct RClass. Place m_tbl instead. */
//   struct rb_id_table *m_tbl;
// #endif
};

rb_serial_t RCLASS_SERIAL(VALUE obj) {
  if (sizeof(rb_serial_t) == sizeof(VALUE)) {
    return ((struct RClass*)obj)->class_serial;
  } else {
    //return ((struct RClass*)obj)->ptr->class_serial;
    return 0;
  }
}

int rb_call_cache__has_class_serial(struct rb_call_cache* cc, rb_serial_t class_serial) {
  int ret = 2;
  size_t i=0;
  for (; i < (sizeof(cc->class_serial)/sizeof(cc->class_serial[0])); i++) {
    rb_serial_t s = cc->class_serial[i];
    if (s == 0) {
      return ret+i;
    } else if (s != class_serial) {
      continue;
    }
    return 1;
  }
  return ret+i;
}

const rb_callable_method_entry_t* rb_call_cache__me(struct rb_call_cache* cc) {
  return cc->me;
}

void* rb_call_cache__call(struct rb_call_cache* cc) {
  return (void*)(cc->call);
}

const struct rb_method_definition_struct* rb_callable_method_entry_t__def(rb_callable_method_entry_t* me) {
  return me->def;
}

void* rb_method_definition_struct__cfunc__func(struct rb_method_definition_struct* def) {
  return (void*)(def->body.cfunc.func);
}

void* rb_method_definition_struct__cfunc__invoker(struct rb_method_definition_struct* def) {
  return (void*)(def->body.cfunc.invoker);
}

int rb_method_definition_struct__cfunc__argc(struct rb_method_definition_struct* def) {
  return def->body.cfunc.argc;
}

ID rb_method_definition_struct__original_id(struct rb_method_definition_struct* def) {
  return def->original_id;
}

ID rb_call_info__mid(struct rb_call_info* ci) {
  return ci->mid;
}

int rb_call_info__orig_argc(struct rb_call_info* ci) {
  return ci->orig_argc;
}

unsigned int rb_call_info__flag(const struct rb_call_info* ci) {
  return ci->flag;
}

struct rb_call_info_kw_arg* rb_call_info_with_kwarg__kw_arg(struct rb_call_info_with_kwarg* ci) {
  return ci->kw_arg;
}

int rb_call_info_kw_arg__keyword_len(struct rb_call_info_kw_arg* kw_args) {
  return kw_args->keyword_len;
}

VALUE* rb_call_info_kw_arg__keywords(struct rb_call_info_kw_arg* kw_args) {
  return &kw_args->keywords[0];
}

////

typedef struct rb_code_position_struct {
  int lineno;
  int column;
} rb_code_position_t;

typedef struct rb_code_location_struct {
  rb_code_position_t beg_pos;
  rb_code_position_t end_pos;
} rb_code_location_t;

typedef struct rb_iseq_location_struct {
  VALUE pathobj;
  VALUE base_label;
  VALUE label;
  VALUE first_lineno;
  int node_id;
  rb_code_location_t code_location;
} rb_iseq_location_t;

typedef uint32_t rb_event_flag_t;
struct iseq_insn_info_entry {
  int line_no;
  rb_event_flag_t events;
};

// 0: linear search , 1: binary search, 2: succinct bitvector
#define VM_INSN_INFO_TABLE_IMPL 2

typedef signed long rb_snum_t;

struct rb_iseq_struct;

struct rb_iseq_constant_body {
  enum iseq_type {
    ISEQ_TYPE_TOP,
    ISEQ_TYPE_METHOD,
    ISEQ_TYPE_BLOCK,
    ISEQ_TYPE_CLASS,
    ISEQ_TYPE_RESCUE,
    ISEQ_TYPE_ENSURE,
    ISEQ_TYPE_EVAL,
    ISEQ_TYPE_MAIN,
    ISEQ_TYPE_PLAIN
  } type;
  
  unsigned int iseq_size;
  const VALUE *iseq_encoded;

  struct {
    struct {
      unsigned int has_lead   : 1;
      unsigned int has_opt    : 1;
      unsigned int has_rest   : 1;
      unsigned int has_post   : 1;
      unsigned int has_kw     : 1;
      unsigned int has_kwrest : 1;
      unsigned int has_block  : 1;

      unsigned int ambiguous_param0 : 1;
      unsigned int accepts_no_kwarg : 1;
      unsigned int ruby2_keywords: 1;
    } flags;

    unsigned int size;

    int lead_num;
    int opt_num;
    int rest_start;
    int post_start;
    int post_num;
    int block_start;

    const VALUE *opt_table;

    const struct rb_iseq_param_keyword {
      int num;
      int required_num;
      int bits_start;
      int rest_start;
      const ID *table;
      VALUE *default_values;
    } *keyword;
  } param;

  rb_iseq_location_t location;

  struct iseq_insn_info {
    /*const struct iseq_insn_info_entry*/void *body;
    unsigned int *positions;
    unsigned int size;
#if VM_INSN_INFO_TABLE_IMPL == 2
    /*struct succ_index_table*/void *succ_index_table;
#endif
  } insns_info;

  const ID *local_table;

  const /*struct iseq_catch_table*/void *catch_table;

  const struct rb_iseq_struct *parent_iseq;
  struct rb_iseq_struct *local_iseq;

  /*union iseq_inline_storage_entry*/void *is_entries;
  struct rb_call_data *call_data;


  struct {
    rb_snum_t flip_count;
    VALUE coverage;
    VALUE pc2branchindex;
    VALUE *original_iseq;
  } variable;

  unsigned int local_table_size;

  //...
};

struct rb_iseq_struct {
  VALUE flags;
  VALUE wrapper;

  struct rb_iseq_constant_body *body;

  //...
};
typedef struct rb_iseq_struct rb_iseq_t;

ID local_var_id(const rb_iseq_t *diseq, VALUE level, int idx) {
  for (int i = 0; i < level; i++) {
      diseq = diseq->body->parent_iseq;
  }
  ID lid = diseq->body->local_table[idx];
  return lid;
}

int local_var_idx(const rb_iseq_t *diseq, VALUE level, VALUE op) {
  for (int i = 0; i < level; i++) {
      diseq = diseq->body->parent_iseq;
  }
  int idx = diseq->body->local_table_size - (int)op - 1;
  return idx;
}

size_t get_local_table_size_at_level(const rb_iseq_t *diseq, VALUE level) {
  for (int i = 0; i < level; i++) {
    diseq = diseq->body->parent_iseq;
  }
  return diseq->body->local_table_size;
}

size_t get_local_table_size(const rb_iseq_t *diseq) {
  return diseq->body->local_table_size;
}

////

typedef struct rb_control_frame_struct {
  const VALUE *pc;
  VALUE *sp;
  const rb_iseq_t *iseq;
  VALUE self;
  const VALUE *ep; // GET_EP
  const void *block_code;
  VALUE *__bp__;

// #if VM_DEBUG_BP_CHECK
//   VALUE *bp_check;
// #endif
} rb_control_frame_t;

enum ruby_tag_type {
  RUBY_TAG_NONE       = 0x0,
  RUBY_TAG_RETURN     = 0x1,
  RUBY_TAG_BREAK      = 0x2,
  RUBY_TAG_NEXT       = 0x3,
  RUBY_TAG_RETRY      = 0x4,
  RUBY_TAG_REDO       = 0x5,
  RUBY_TAG_RAISE      = 0x6,
  RUBY_TAG_THROW      = 0x7,
  RUBY_TAG_FATAL      = 0x8,
  RUBY_TAG_MASK       = 0xf
};

typedef void *rb_jmpbuf_t[5];

struct rb_vm_tag {
  VALUE tag;
  VALUE retval;
  rb_jmpbuf_t buf;
  struct rb_vm_tag *prev;
  enum ruby_tag_type state;
};

typedef unsigned int rb_atomic_t;

// vm.ec_p
// just the early parts of the struct
typedef struct rb_execution_context_struct {
  VALUE *vm_stack;
  size_t vm_stack_size;
  rb_control_frame_t *cfp;

  struct rb_vm_tag *tag;
  /*struct rb_vm_protect_tag*/void *protect_tag;

  rb_atomic_t interrupt_flag;
  rb_atomic_t interrupt_mask;

  /*rb_fiber_t*/void *fiber_ptr;
  /*struct rb_thread_struct*/void *thread_ptr;

  /*st_table*/void *local_storage;
  VALUE local_storage_recursive_hash;
  VALUE local_storage_recursive_hash_for_trace;

  const VALUE *root_lep;
  VALUE root_svar;

  /*rb_ensure_list_t*/void *ensure_list;

  /*struct rb_trace_arg_struct*/void *trace_arg;

  VALUE errinfo;
} rb_execution_context_t;

rb_control_frame_t* rb_execution_context_struct__cfp(rb_execution_context_t* ec) {
  return ec->cfp;
}
struct rb_vm_tag* rb_execution_context_struct__tag(struct rb_execution_context_struct* ec) {
  return ec->tag;
}
void* rb_execution_context_struct__thread_ptr(struct rb_execution_context_struct* ec) {
  return ec->thread_ptr;
}
VALUE rb_execution_context_struct__errinfo(struct rb_execution_context_struct* ec) {
  return ec->errinfo;
}

VALUE rb_vm_tag__tag(struct rb_vm_tag* tag) {
  return tag->tag;
}
VALUE rb_vm_tag__retval(struct rb_vm_tag* tag) {
  return tag->retval;
}
struct rb_vm_tag* rb_vm_tag__prev(struct rb_vm_tag* tag) {
  return tag->prev;
}
int rb_vm_tag__state(struct rb_vm_tag* tag) {
  return (int)(tag->state);
}

const VALUE* rb_control_frame_t__pc(rb_control_frame_t* cfp) {
  return cfp->pc;
}
VALUE* rb_control_frame_t__sp(rb_control_frame_t* cfp) {
  return cfp->sp;
}
const rb_iseq_t* rb_control_frame_t__iseq(rb_control_frame_t* cfp) {
  return cfp->iseq;
}
VALUE rb_control_frame_t__self(rb_control_frame_t* cfp) {
  return cfp->self;
}
const VALUE* rb_control_frame_t__ep(rb_control_frame_t* cfp) {
  return cfp->ep;
}

////

typedef enum {
  METHOD_VISI_UNDEF     = 0x00,
  METHOD_VISI_PUBLIC    = 0x01,
  METHOD_VISI_PRIVATE   = 0x02,
  METHOD_VISI_PROTECTED = 0x03,

  METHOD_VISI_MASK = 0x03
} rb_method_visibility_t;

typedef struct rb_scope_visi_struct {
  rb_method_visibility_t method_visi : 3;
  unsigned int module_func : 1;
} rb_scope_visibility_t;

typedef struct rb_cref_struct {
  VALUE flags;
  VALUE refinements;
  VALUE klass;
  struct rb_cref_struct * next;
  const rb_scope_visibility_t scope_visi;
} rb_cref_t;

VALUE rb_cref_t__klass(rb_cref_t* cref) {
  return cref->klass;
}

////

struct rb_global_entry {
  /*struct rb_global_variable*/void *var;
  ID id;
};

ID rb_global_entry__id(struct rb_global_entry* entry) {
  return entry->id;
}

////

enum {
  VM_FRAME_MAGIC_METHOD = 0x11110001,
  VM_FRAME_MAGIC_BLOCK  = 0x22220001,
  VM_FRAME_MAGIC_CLASS  = 0x33330001,
  VM_FRAME_MAGIC_TOP    = 0x44440001,
  VM_FRAME_MAGIC_CFUNC  = 0x55550001,
  VM_FRAME_MAGIC_IFUNC  = 0x66660001,
  VM_FRAME_MAGIC_EVAL   = 0x77770001,
  VM_FRAME_MAGIC_RESCUE = 0x78880001,
  VM_FRAME_MAGIC_DUMMY  = 0x79990001,

  VM_FRAME_MAGIC_MASK   = 0x7fff0001,

  VM_FRAME_FLAG_PASSED    = 0x0010,
  VM_FRAME_FLAG_FINISH    = 0x0020,
  VM_FRAME_FLAG_BMETHOD   = 0x0040,
  VM_FRAME_FLAG_CFRAME    = 0x0080,
  VM_FRAME_FLAG_LAMBDA    = 0x0100,
  VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM = 0x0200,
  VM_FRAME_FLAG_CFRAME_KW = 0x0400,
  VM_FRAME_FLAG_CFRAME_EMPTY_KW = 0x0800,

  VM_ENV_FLAG_LOCAL       = 0x0002,
  VM_ENV_FLAG_ESCAPED     = 0x0004,
  VM_ENV_FLAG_WB_REQUIRED = 0x0008
};

#define VM_ENV_DATA_INDEX_SPECVAL (-1)
#define VM_ENV_DATA_INDEX_FLAGS (0)

static inline unsigned long VM_ENV_FLAGS(const VALUE *ep, long flag) {
  VALUE flags = ep[VM_ENV_DATA_INDEX_FLAGS];
  return flags & flag;
}

static inline int VM_ENV_LOCAL_P(const VALUE *ep) {
  return VM_ENV_FLAGS(ep, VM_ENV_FLAG_LOCAL) ? 1 : 0;
}

#define VM_TAGGED_PTR_REF(v, mask) ((void *)((v) & ~mask))
#define GC_GUARDED_PTR_REF(p) VM_TAGGED_PTR_REF((p), 0x03)

static inline const VALUE* VM_ENV_PREV_EP(const VALUE *ep) {
  return GC_GUARDED_PTR_REF(ep[VM_ENV_DATA_INDEX_SPECVAL]);
}

const VALUE* VM_EP_LEP(const VALUE *ep) {
  while (!VM_ENV_LOCAL_P(ep)) {
    ep = VM_ENV_PREV_EP(ep);
  }
  return ep;
}

////

struct iter_method_arg {
  VALUE obj;
  ID mid;
  int argc;
  const VALUE *argv;
  int kw_splat;
};

VALUE iter_method_arg__obj(struct iter_method_arg* ima) {
  return ima->obj;
}

ID iter_method_arg__mid(struct iter_method_arg* ima) {
  return ima->mid;
}

int iter_method_arg__argc(struct iter_method_arg* ima) {
  return ima->argc;
}

const VALUE* iter_method_arg__argv(struct iter_method_arg* ima) {
  return ima->argv;
}

int iter_method_arg__kw_splat(struct iter_method_arg* ima) {
  return ima->kw_splat;
}

////

#define SIZEOF_INT 4
#define SIZEOF_VALUE 8
#define CHAR_BIT 8

struct vm_ifunc_argc {
  #if SIZEOF_INT * 2 > SIZEOF_VALUE
    signed int min: (SIZEOF_VALUE * CHAR_BIT) / 2;
    signed int max: (SIZEOF_VALUE * CHAR_BIT) / 2;
  #else
    int min, max;
  #endif
};

#define RB_BLOCK_CALL_FUNC_ARGLIST(yielded_arg, callback_arg) \
  VALUE yielded_arg, VALUE callback_arg, int argc, const VALUE *argv, VALUE blockarg

typedef VALUE rb_block_call_func(RB_BLOCK_CALL_FUNC_ARGLIST(yielded_arg, callback_arg));
typedef rb_block_call_func *rb_block_call_func_t;

struct vm_ifunc {
  VALUE flags;
  VALUE reserved;
  rb_block_call_func_t func;
  const void *data;
  struct vm_ifunc_argc argc;
};

const void* vm_ifunc__data(struct vm_ifunc* ifunc) {
  return ifunc->data;
}

void* vm_ifunc__func(struct vm_ifunc* ifunc) {
  return (void*)(ifunc->func);
}

////

struct vm_throw_data {
  VALUE flags;
  VALUE reserved;
  const VALUE throw_obj;
  const struct rb_control_frame_struct *catch_frame;
  int throw_state;
};

VALUE vm_throw_data__flags(struct vm_throw_data* obj) {
  return obj->flags;
}
const VALUE vm_throw_data__throw_obj(struct vm_throw_data* obj) {
  return obj->throw_obj;
}
const struct rb_control_frame_struct* vm_throw_data__catch_frame(struct vm_throw_data* obj) {
  return obj->catch_frame;
}
int vm_throw_data__throw_state(struct vm_throw_data* obj) {
  return obj->throw_state;
}

////

struct iseq_inline_cache_entry {
  rb_serial_t ic_serial;
  const /*rb_cref_t*/void *ic_cref;
  VALUE value;
};

size_t iseq_inline_cache_entry__ic_serial(struct iseq_inline_cache_entry* ic) {
  return ic->ic_serial;
}

const void* iseq_inline_cache_entry__ic_cref(struct iseq_inline_cache_entry* ic) {
  return ic->ic_cref;
}

VALUE iseq_inline_cache_entry__value(struct iseq_inline_cache_entry* ic) {
  return ic->value;
}

////

struct iseq_inline_iv_cache_entry {
  rb_serial_t ic_serial;
  size_t index;
};

union iseq_inline_storage_entry {
  struct {
      struct rb_thread_struct *running_thread;
      VALUE value;
  } once;
  struct iseq_inline_cache_entry cache;
  struct iseq_inline_iv_cache_entry iv_cache;
};

void* iseq_inline_storage_entry__once_running_thread(union iseq_inline_storage_entry* ise) {
  return ise->once.running_thread;
}

VALUE iseq_inline_storage_entry__once_value(union iseq_inline_storage_entry* ise) {
  return ise->once.value;
}

////
typedef struct pthread_mutex {
  char unk[40]; 
} pthread_mutex_t;

typedef pthread_mutex_t rb_nativethread_lock_t;

typedef struct pthread_cond {
  char unk[48];
  char pad[4];
} pthread_cond_t;

typedef pthread_cond_t rb_nativethread_cond_t;

struct list_node {
  /*struct list_node*/void *next, *prev;
};

struct list_head {
  struct list_node n;
};

// typedef unsigned char _Bool;
#define bool _Bool

enum ruby_special_exceptions {
  ruby_error_reenter,
  ruby_error_nomemory,
  ruby_error_sysstack,
  ruby_error_stackfatal,
  ruby_error_stream_closed,
  ruby_special_error_count
};

enum ruby_basic_operators {
  BOP_PLUS,
  BOP_MINUS,
  BOP_MULT,
  BOP_DIV,
  BOP_MOD,
  BOP_EQ,
  BOP_EQQ,
  BOP_LT,
  BOP_LE,
  BOP_LTLT,
  BOP_AREF,
  BOP_ASET,
  BOP_LENGTH,
  BOP_SIZE,
  BOP_EMPTY_P,
  BOP_NIL_P,
  BOP_SUCC,
  BOP_GT,
  BOP_GE,
  BOP_NOT,
  BOP_NEQ,
  BOP_MATCH,
  BOP_FREEZE,
  BOP_UMINUS,
  BOP_MAX,
  BOP_MIN,
  BOP_CALL,
  BOP_AND,
  BOP_OR,

  BOP_LAST_
};

#define NSIG 65 // linux
#define RUBY_NSIG NSIG

typedef struct rb_global_vm_lock_struct {
  const /*struct rb_thread_struct*/void *owner;
  rb_nativethread_lock_t lock;

  struct list_head waitq;
  const /*struct rb_thread_struct*/void *timer;
  int timer_err;

  rb_nativethread_cond_t switch_cond;
  rb_nativethread_cond_t switch_wait_cond;
  int need_yield;
  int wait_yield;
} rb_global_vm_lock_t;

typedef struct rb_hook_list_struct {
  /*struct rb_event_hook_struct*/void *hooks;
  rb_event_flag_t events;
  unsigned int need_clean;
  unsigned int running;
} rb_hook_list_t;

typedef struct rb_vm_struct {
  VALUE self;

  rb_global_vm_lock_t gvl;

  /*struct rb_thread_struct*/void *main_thread;

  const /*struct rb_thread_struct*/void *running_thread;

//#ifdef USE_SIGALTSTACK
// ${vm.USE_SIGALTSTACK}
#if ${vm.USE_SIGALTSTACK == "USE_SIGALTSTACK" ? "1" : "0"}
  void *main_altstack;
#endif

  rb_serial_t fork_gen;
  rb_nativethread_lock_t waitpid_lock;
  struct list_head waiting_pids;
  struct list_head waiting_grps;
  struct list_head waiting_fds;
  struct list_head living_threads;
  VALUE thgroup_default;
  int living_thread_num;

  volatile int ubf_async_safe;

  unsigned int running: 1;
  unsigned int thread_abort_on_exception: 1;
  unsigned int thread_report_on_exception: 1;

  unsigned int safe_level_: 1;
  int sleeper;

  VALUE mark_object_ary;
  const VALUE special_exceptions[ruby_special_error_count];

  VALUE top_self;
  VALUE load_path;
  VALUE load_path_snapshot;
  VALUE load_path_check_cache;
  VALUE expanded_load_path;
  VALUE loaded_features;
  VALUE loaded_features_snapshot;
  /*struct st_table*/void *loaded_features_index;
  /*struct st_table*/void *loading_table;

  struct {
    VALUE cmd[RUBY_NSIG];
  } trap_list;

  rb_hook_list_t global_hooks;

  /*struct st_table*/void *ensure_rollback_table;

  /*struct rb_postponed_job_struct*/void *postponed_job_buffer;
  int postponed_job_index;

  int src_encoding_index;

  struct list_head workqueue;
  rb_nativethread_lock_t workqueue_lock;

  VALUE verbose, debug, orig_progname, progname;
  VALUE coverages;
  int coverage_mode;

  /*st_table*/void * defined_module_hash;

  /*struct rb_objspace*/void *objspace;

  /*rb_at_exit_list*/void *at_exit;

  VALUE *defined_strings;
  /*st_table*/void *frozen_strings;

  const /*struct rb_builtin_function*/void *builtin_function_table;
  int builtin_inline_index;

  struct {
    size_t thread_vm_stack_size;
    size_t thread_machine_stack_size;
    size_t fiber_vm_stack_size;
    size_t fiber_machine_stack_size;
  } default_params;

  short redefined_flag[BOP_LAST_];
} rb_vm_t;

short rb_vm_struct__redefined_flag(rb_vm_t* vm, size_t idx) {
  return vm->redefined_flag[idx];
}

////

bool RB_IMMEDIATE_P(VALUE obj, int USE_FLONUM) {
  if (USE_FLONUM) {
    return obj & 0x07;
  } else {
    return obj & 0x03;
  }
}

bool RB_TEST(VALUE obj, int USE_FLONUM) {
  if (USE_FLONUM) {
    return obj & ~0x08;
  } else {
    return obj & ~0x04;
  }
}

bool RB_SPECIAL_CONST_P(VALUE obj, int USE_FLONUM) {
    return RB_IMMEDIATE_P(obj, USE_FLONUM) || ! RB_TEST(obj, USE_FLONUM);
}

#define RBIMPL_CAST(expr) (expr)
#define RBASIC(obj) RBIMPL_CAST((struct RBasic *)(obj))

#define RUBY_T_MASK 0x1f

int RB_BUILTIN_TYPE(VALUE obj) {
  VALUE ret = RBASIC(obj)->flags & RUBY_T_MASK;
  return (int)ret;
}

int rb_obj_builtin_type(VALUE obj, int USE_FLONUM) {
  return RB_SPECIAL_CONST_P(obj, USE_FLONUM) ? -1 : (int)RB_BUILTIN_TYPE(obj);
}

////

struct rb_builtin_function {
  const void * const func_ptr;
  const int argc;

  const int index;
  const char * const name;

  void (*compiler)(/*FILE*/void *, long, unsigned, bool);
};

const void* rb_builtin_function__func_ptr(struct rb_builtin_function* bf) {
  return bf->func_ptr;
}

const char* const rb_builtin_function__name(struct rb_builtin_function* bf) {
  return bf->name;
}
`;

// console.log(code)
const cm = new CModule(code);

const VALUE = 'pointer';
const ID = 'pointer';

return {
  rb_calling_info__recv: new NativeFunction(cm.rb_calling_info__recv, VALUE, ['pointer']),
  rb_calling_info__argc: new NativeFunction(cm.rb_calling_info__argc, 'int', ['pointer']),
  rb_call_data__cc: new NativeFunction(cm.rb_call_data__cc, 'pointer', ['pointer']),
  rb_call_data__ci: new NativeFunction(cm.rb_call_data__ci, 'pointer', ['pointer']),
  RCLASS_SERIAL: new NativeFunction(cm.RCLASS_SERIAL, 'size_t', [VALUE]),
  rb_call_cache__has_class_serial: new NativeFunction(cm.rb_call_cache__has_class_serial, 'int', ['pointer', 'size_t']),
  rb_call_cache__me: new NativeFunction(cm.rb_call_cache__me, 'pointer', ['pointer']),
  rb_call_cache__call: new NativeFunction(cm.rb_call_cache__call, 'pointer', ['pointer']),
  rb_callable_method_entry_t__def: new NativeFunction(cm.rb_callable_method_entry_t__def, 'pointer', ['pointer']),
  rb_method_definition_struct__cfunc__func: new NativeFunction(cm.rb_method_definition_struct__cfunc__func, 'pointer', ['pointer']),
  rb_method_definition_struct__cfunc__invoker: new NativeFunction(cm.rb_method_definition_struct__cfunc__invoker, 'pointer', ['pointer']),
  rb_method_definition_struct__cfunc__argc: new NativeFunction(cm.rb_method_definition_struct__cfunc__argc, 'int', ['pointer']),
  rb_method_definition_struct__original_id: new NativeFunction(cm.rb_method_definition_struct__original_id, ID, ['pointer']),
  rb_call_info__mid: new NativeFunction(cm.rb_call_info__mid, ID, ['pointer']),
  rb_call_info__orig_argc: new NativeFunction(cm.rb_call_info__orig_argc, 'int', ['pointer']),
  rb_call_info__flag: new NativeFunction(cm.rb_call_info__flag, 'int', ['pointer']),
  rb_call_info_with_kwarg__kw_arg: new NativeFunction(cm.rb_call_info_with_kwarg__kw_arg, 'pointer', ['pointer']),
  rb_call_info_kw_arg__keyword_len: new NativeFunction(cm.rb_call_info_kw_arg__keyword_len, 'int', ['pointer']),
  rb_call_info_kw_arg__keywords: new NativeFunction(cm.rb_call_info_kw_arg__keywords, 'pointer', ['pointer']),
  rb_cref_t__klass: new NativeFunction(cm.rb_cref_t__klass, VALUE, ['pointer']),
  rb_execution_context_struct__cfp: new NativeFunction(cm.rb_execution_context_struct__cfp, 'pointer', ['pointer']),
  rb_execution_context_struct__tag: new NativeFunction(cm.rb_execution_context_struct__tag, 'pointer', ['pointer']),
  rb_execution_context_struct__thread_ptr: new NativeFunction(cm.rb_execution_context_struct__thread_ptr, 'pointer', ['pointer']),
  rb_execution_context_struct__errinfo: new NativeFunction(cm.rb_execution_context_struct__errinfo, VALUE, ['pointer']),
  rb_vm_tag__tag: new NativeFunction(cm.rb_vm_tag__tag, VALUE, ['pointer']),
  rb_vm_tag__retval: new NativeFunction(cm.rb_vm_tag__tag, VALUE, ['pointer']),
  rb_vm_tag__prev: new NativeFunction(cm.rb_vm_tag__tag, 'pointer', ['pointer']),
  rb_vm_tag__state: new NativeFunction(cm.rb_vm_tag__state, 'int', ['pointer']),
  rb_control_frame_t__pc: new NativeFunction(cm.rb_control_frame_t__pc, 'pointer', ['pointer']),
  rb_control_frame_t__sp: new NativeFunction(cm.rb_control_frame_t__sp, 'pointer', ['pointer']),
  rb_control_frame_t__iseq: new NativeFunction(cm.rb_control_frame_t__iseq, 'pointer', ['pointer']),
  rb_control_frame_t__self: new NativeFunction(cm.rb_control_frame_t__self, VALUE, ['pointer']),
  rb_control_frame_t__ep: new NativeFunction(cm.rb_control_frame_t__ep, 'pointer', ['pointer']),
  rb_global_entry__id: new NativeFunction(cm.rb_global_entry__id, ID, ['pointer']),
  local_var_id: new NativeFunction(cm.local_var_id, ID, ['pointer', VALUE, 'int']),
  local_var_idx: new NativeFunction(cm.local_var_idx, 'int', ['pointer', VALUE, VALUE]),
  get_local_table_size: new NativeFunction(cm.get_local_table_size, 'size_t', ['pointer']),
  get_local_table_size_at_level: new NativeFunction(cm.get_local_table_size_at_level, 'size_t', ['pointer', VALUE]),
  VM_EP_LEP: new NativeFunction(cm.VM_EP_LEP, 'pointer', ['pointer']),
  iter_method_arg__obj: new NativeFunction(cm.iter_method_arg__obj, VALUE, ['pointer']),
  iter_method_arg__mid: new NativeFunction(cm.iter_method_arg__mid, ID, ['pointer']),
  iter_method_arg__argc: new NativeFunction(cm.iter_method_arg__argc, 'int', ['pointer']),
  iter_method_arg__argv: new NativeFunction(cm.iter_method_arg__argv, 'pointer', ['pointer']),
  iter_method_arg__kw_splat: new NativeFunction(cm.iter_method_arg__kw_splat, 'int', ['pointer']),
  vm_ifunc__data: new NativeFunction(cm.vm_ifunc__data, 'pointer', ['pointer']),
  vm_ifunc__func: new NativeFunction(cm.vm_ifunc__func, 'pointer', ['pointer']),
  vm_throw_data__flags: new NativeFunction(cm.vm_throw_data__flags, VALUE, ['pointer']),
  vm_throw_data__throw_obj: new NativeFunction(cm.vm_throw_data__throw_obj, VALUE, ['pointer']),
  vm_throw_data__catch_frame: new NativeFunction(cm.vm_throw_data__catch_frame, 'pointer', ['pointer']),
  vm_throw_data__throw_state: new NativeFunction(cm.vm_throw_data__flags, 'int', ['pointer']),
  iseq_inline_cache_entry__ic_serial: new NativeFunction(cm.iseq_inline_cache_entry__ic_serial, 'size_t', ['pointer']),
  iseq_inline_cache_entry__ic_cref: new NativeFunction(cm.iseq_inline_cache_entry__ic_cref, 'pointer', ['pointer']),
  iseq_inline_cache_entry__value: new NativeFunction(cm.iseq_inline_cache_entry__value, VALUE, ['pointer']),
  iseq_inline_storage_entry__once_running_thread: new NativeFunction(cm.iseq_inline_storage_entry__once_running_thread, 'pointer', ['pointer']),
  iseq_inline_storage_entry__once_value: new NativeFunction(cm.iseq_inline_storage_entry__once_value, VALUE, ['pointer']),
  rb_vm_struct__redefined_flag: new NativeFunction(cm.rb_vm_struct__redefined_flag, 'int16', ['pointer', 'size_t']),
  rb_obj_builtin_type: new NativeFunction(cm.rb_obj_builtin_type, 'int', [VALUE, 'int']),
  rb_builtin_function__func_ptr: new NativeFunction(cm.rb_builtin_function__func_ptr, 'pointer', ['pointer']),
  rb_builtin_function__name: new NativeFunction(cm.rb_builtin_function__name, 'pointer', ['pointer']),

  cm // must not be gc'd
}

}