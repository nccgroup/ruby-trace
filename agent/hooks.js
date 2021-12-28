/*
Copyright (c) 2021 NCC Group Security Services, Inc. All rights reserved.

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

let r = require('./ruby')();
let vm = require('./rubyvm')();
let { log } = require('./libc')();

const VALUE = 'pointer';
const ID = 'pointer';

const insnhooks = require('./insnhooks')

const unhookables = new Set([
  "rb_false",
  "rb_obj_itself",
  "false_and",
  "enc_load",
  "sym_to_sym",
  "name_err_mesg_load",
  "obj_respond_to_missing",
  "num_uplus",
  "num_int_p",
  "flo_to_f",
  "rb_ary_to_ary_m",
  "rb_ary_deconstruct",
  "rb_hash_to_hash",
  "rb_hash_deconstruct_keys",
  "rb_io_to_io",
  "proc_to_proc",
  "lazy_lazy",
  "mutex_initialize",
  "nurat_to_r",
  "integer_numerator",
  "nucomp_false",
  "nucomp_to_c",
  "numeric_real",
  "numeric_conj",

  // this one
  // "nil_to_h", //note: this seems to have triggered
                 // CHECK_CFP_CONSISTENCY("vm_call0_cfunc_with_frame")
                 // in vm_eval.c, but only when we did a rb_hash_inspect from
                 // static_inspect on the actual object undergoing an
                 // rb_hash_aref. once we fixed that, this went away.
                 // (...for now at least)

  /*
  "rb_int_equal",
  "rb_obj_equal",
  "rb_obj_not",
  "rb_obj_not_equal",
  "rb_equal",
  "rb_obj_match",
  "rb_obj_not_match",
  "rb_obj_hash",
  "rb_obj_cmp",
  "rb_obj_singleton_class",
  "rb_obj_dup",
  "rb_obj_init_copy",
  "rb_obj_init_dup_clone",
  "rb_obj_init_clone",
  "rb_obj_taint",
  "rb_obj_tainted",
  "rb_obj_untaint",
  "rb_obj_untrust",
  "rb_obj_untrusted",
  "rb_obj_trust",
  "rb_obj_freeze",
  "rb_any_to_s",
  "rb_obj_inspect",
  "rb_obj_methods",
  "rb_obj_singleton_methods",
  "rb_obj_protected_methods",
  "rb_obj_private_methods",
  "rb_obj_public_methods",
  "rb_obj_instance_variables",
  "rb_obj_ivar_get",
  "rb_obj_ivar_set",
  "rb_obj_ivar_defined",
  "rb_obj_remove_instance_variable",
  "rb_obj_is_instance_of",
  "rb_obj_is_kind_of",
  "f_sprintf",
  "rb_f_integer",
  "rb_f_string",
  "rb_f_array",
  "rb_f_hash",
  "nil_to_i",
  "nil_to_f",
  "nil_to_s",
  "nil_to_a",
  "nil_inspect",
  "nil_match",
  "true_and",
  "rb_true",
  "rb_mod_freeze",
  "rb_mod_eqq",
  "rb_mod_cmp",
  "rb_mod_lt",
  "rb_class_inherited_p",
  "rb_mod_gt",
  "rb_mod_ge",
  "rb_mod_init_copy",
  "rb_mod_to_s",
  "rb_mod_included_modules",
  "rb_mod_include_p",
  "rb_mod_name",
  "rb_mod_ancestors",
  "rb_mod_attr",
  "rb_mod_attr_reader",
  "rb_mod_attr_writer",
  "rb_mod_attr_accessor",
  "rb_mod_initialize",
  "rb_mod_initialize_clone",
  "rb_class_instance_methods",
  "rb_class_public_instance_methods",
  "rb_class_protected_instance_methods",
  "rb_class_private_instance_methods",
  "rb_mod_constants",
  "rb_mod_const_get",
  "rb_mod_const_set",
  "rb_mod_const_defined",
  "rb_mod_const_source_location",
  "rb_mod_const_missing",
  "rb_mod_class_variables",
  "rb_mod_remove_cvar",
  "rb_mod_cvar_get",
  "rb_mod_cvar_set",
  "rb_mod_cvar_defined",
  "rb_mod_public_constant",
  "rb_mod_private_constant",
  "rb_mod_deprecate_constant",
  "rb_mod_singleton_p",
  "rb_class_alloc_m",
  "rb_class_new_instance_pass_kw",
  "rb_class_initialize",
  "rb_class_superclass",
  "true_to_s",
  "true_or",
  "true_xor",
  "false_to_s",
  "main_to_s",
  "enc_name",
  "enc_inspect",
  "enc_names",
  "enc_dummy_p",
  "enc_ascii_compatible_p",
  "enc_replicate_m",
  "enc_list",
  "rb_enc_name_list",
  "rb_enc_aliases",
  "enc_find",
  "enc_compatible_p",
  "enc_dump",
  "get_default_external",
  "set_default_external",
  "get_default_internal",
  "set_default_internal",
  "rb_locale_charmap",
  "cmp_equal",
  "cmp_gt",
  "cmp_ge",
  "cmp_lt",
  "cmp_le",
  "cmp_between",
  "cmp_clamp",
  "enum_to_a",
  "enum_to_h",
  "enum_sort",
  "enum_sort_by",
  "enum_grep",
  "enum_grep_v",
  "enum_count",
  "enum_find",
  "enum_find_index",
  "enum_find_all",
  "enum_filter_map",
  "enum_reject",
  "enum_collect",
  "enum_flat_map",
  "enum_inject",
  "enum_partition",
  "enum_group_by",
  "enum_tally",
  "enum_first",
  "enum_all",
  "enum_any",
  "enum_one",
  "enum_none",
  "enum_min",
  "enum_max",
  "enum_minmax",
  "enum_min_by",
  "enum_max_by",
  "enum_minmax_by",
  "enum_member",
  "enum_each_with_index",
  "enum_reverse_each",
  "enum_each_entry",
  "enum_each_slice",
  "enum_each_cons",
  "enum_each_with_object",
  "enum_zip",
  "enum_take",
  "enum_take_while",
  "enum_drop",
  "enum_drop_while",
  "enum_cycle",
  "enum_chunk",
  "enum_slice_before",
  "enum_slice_after",
  "enum_slice_when",
  "enum_chunk_while",
  "enum_sum",
  "enum_uniq",
  "rb_str_s_try_convert",
  "rb_str_init",
  "rb_str_replace",
  "rb_str_cmp_m",
  "rb_str_equal",
  "rb_str_eql",
  "rb_str_hash_m",
  "rb_str_casecmp",
  "rb_str_casecmp_p",
  "rb_str_plus",
  "rb_str_times",
  "rb_str_format_m",
  "rb_str_aref_m",
  "rb_str_aset_m",
  "rb_str_insert",
  "rb_str_length",
  "rb_str_bytesize",
  "rb_str_empty",
  "rb_str_match",
  "rb_str_match_m",
  "rb_str_match_m_p",
  "rb_str_succ",
  "rb_str_succ_bang",
  "rb_str_upto",
  "rb_str_index_m",
  "rb_str_rindex_m",
  "rb_str_clear",
  "rb_str_chr",
  "rb_str_getbyte",
  "rb_str_setbyte",
  "rb_str_byteslice",
  "str_scrub",
  "str_scrub_bang",
  "rb_str_freeze",
  "str_uplus",
  "str_uminus",
  "rb_str_to_i",
  "rb_str_to_f",
  "rb_str_to_s",
  "rb_str_inspect",
  "rb_str_dump",
  "str_undump",
  "rb_str_upcase",
  "rb_str_downcase",
  "rb_str_capitalize",
  "rb_str_swapcase",
  "rb_str_upcase_bang",
  "rb_str_downcase_bang",
  "rb_str_capitalize_bang",
  "rb_str_swapcase_bang",
  "rb_str_hex",
  "rb_str_oct",
  "rb_str_split_m",
  "rb_str_lines",
  "rb_str_bytes",
  "rb_str_chars",
  "rb_str_codepoints",
  "rb_str_grapheme_clusters",
  "rb_str_reverse",
  "rb_str_reverse_bang",
  "rb_str_concat_multi",
  "rb_str_concat",
  "rb_str_prepend_multi",
  "rb_str_crypt",
  "rb_str_intern",
  "rb_str_ord",
  "rb_str_include",
  "rb_str_start_with",
  "rb_str_end_with",
  "rb_str_scan",
  "rb_str_ljust",
  "rb_str_rjust",
  "rb_str_center",
  "rb_str_sub",
  "rb_str_gsub",
  "rb_str_chop",
  "rb_str_chomp",
  "rb_str_strip",
  "rb_str_lstrip",
  "rb_str_rstrip",
  "rb_str_delete_prefix",
  "rb_str_delete_suffix",
  "rb_str_sub_bang",
  "rb_str_gsub_bang",
  "rb_str_chop_bang",
  "rb_str_chomp_bang",
  "rb_str_strip_bang",
  "rb_str_lstrip_bang",
  "rb_str_rstrip_bang",
  "rb_str_delete_prefix_bang",
  "rb_str_delete_suffix_bang",
  "rb_str_tr",
  "rb_str_tr_s",
  "rb_str_delete",
  "rb_str_squeeze",
  "rb_str_count",
  "rb_str_tr_bang",
  "rb_str_tr_s_bang",
  "rb_str_delete_bang",
  "rb_str_squeeze_bang",
  "rb_str_each_line",
  "rb_str_each_byte",
  "rb_str_each_char",
  "rb_str_each_codepoint",
  "rb_str_each_grapheme_cluster",
  "rb_str_sum",
  "rb_str_slice_bang",
  "rb_str_partition",
  "rb_str_rpartition",
  "rb_obj_encoding",
  "rb_str_force_encoding",
  "rb_str_b",
  "rb_str_valid_encoding_p",
  "rb_str_is_ascii_only_p",
  "rb_str_unicode_normalize",
  "rb_str_unicode_normalize_bang",
  "rb_str_unicode_normalized_p",
  "sym_all_symbols",
  "sym_inspect",
  "rb_sym_to_s",
  "rb_sym2str",
  "rb_sym_to_proc",
  "sym_succ",
  "sym_cmp",
  "sym_casecmp",
  "sym_casecmp_p",
  "sym_match",
  "sym_aref",
  "sym_length",
  "sym_empty",
  "sym_match_m",
  "sym_match_m_p",
  "sym_upcase",
  "sym_downcase",
  "sym_capitalize",
  "sym_swapcase",
  "sym_start_with",
  "sym_end_with",
  "sym_encoding",
  "rb_class_new_instance",
  "exc_s_to_tty_p",
  "exc_exception",
  "exc_initialize",
  "exc_equal",
  "exc_to_s",
  "exc_message",
  "exc_full_message",
  "exc_inspect",
  "exc_backtrace",
  "exc_backtrace_locations",
  "exc_set_backtrace",
  "exc_cause",
  "exit_initialize",
  "exit_status",
  "exit_success_p",
  "key_err_initialize",
  "key_err_receiver",
  "key_err_key",
  "syntax_error_initialize",
  "name_err_initialize",
  "name_err_name",
  "name_err_receiver",
  "name_err_local_variables",
  "name_err_mesg_equal",
  "name_err_mesg_to_str",
  "name_err_mesg_dump",
  "nometh_err_initialize",
  "nometh_err_args",
  "nometh_err_private_call_p",
  "frozen_err_initialize",
  "syserr_initialize",
  "syserr_errno",
  "syserr_eqq",
  "rb_warning_s_aref",
  "rb_warning_s_aset",
  "rb_warning_s_warn",
  "warning_write",
  "f_raise",
  "f_global_variables",
  "rb_f_method_name",
  "rb_f_callee_name",
  "f_current_dirname",
  "rb_mod_include",
  "rb_mod_prepend",
  "rb_mod_s_used_modules",
  "rb_f_eval",
  "rb_f_local_variables",
  "rb_f_iterator_p",
  "rb_f_block_given_p",
  "rb_f_catch",
  "rb_f_throw",
  "rb_f_loop",
  "rb_obj_instance_eval_internal",
  "rb_obj_instance_exec_internal",
  "rb_f_public_send",
  "rb_mod_module_exec_internal",
  "rb_mod_module_eval_internal",
  "uncaught_throw_init",
  "uncaught_throw_tag",
  "uncaught_throw_value",
  "uncaught_throw_to_s",
  "obj_respond_to",
  "rb_mod_remove_method",
  "rb_mod_undef_method",
  "rb_mod_alias_method",
  "rb_mod_method_defined",
  "rb_mod_public_method_defined",
  "rb_mod_private_method_defined",
  "rb_mod_protected_method_defined",
  "rb_mod_public_method",
  "rb_mod_private_method",
  "rb_mod_nesting",
  "rb_mod_s_constants",
  "rb_obj_extend",
  "f_trace_var",
  "f_untrace_var",
  "rb_f_at_exit",
  "num_sadded",
  "num_coerce",
  "rb_immutable_obj_clone",
  "num_imaginary",
  "num_uminus",
  "num_cmp",
  "num_eql",
  "num_fdiv",
  "num_div",
  "num_divmod",
  "num_modulo",
  "num_remainder",
  "num_abs",
  "num_to_int",
  "num_real_p",
  "num_zero_p",
  "num_nonzero_p",
  "num_finite_p",
  "num_infinite_p",
  "num_floor",
  "num_ceil",
  "num_round",
  "num_truncate",
  "num_step",
  "num_positive_p",
  "num_negative_p",
  "rb_int_s_isqrt",
  "int_to_s",
  "int_allbits_p",
  "int_anybits_p",
  "int_nobits_p",
  "int_upto",
  "int_downto",
  "int_dotimes",
  "rb_int_succ",
  "rb_int_pred",
  "int_chr",
  "int_to_f",
  "int_floor",
  "int_ceil",
  "int_truncate",
  "int_round",
  "rb_int_cmp",
  "rb_int_plus",
  "rb_int_minus",
  "rb_int_mul",
  "rb_int_div",
  "rb_int_idiv",
  "rb_int_modulo",
  "int_remainder",
  "rb_int_divmod",
  "rb_int_fdiv",
  "rb_int_pow",
  "rb_int_powm",
  "rb_int_gt",
  "rb_int_ge",
  "int_lt",
  "int_le",
  "rb_int_and",
  "int_or",
  "int_xor",
  "int_aref",
  "rb_int_lshift",
  "rb_int_rshift",
  "int_size",
  "rb_int_digits",
  "flo_to_s",
  "flo_coerce",
  "rb_float_uminus",
  "rb_float_plus",
  "rb_float_minus",
  "rb_float_mul",
  "rb_float_div",
  "flo_quo",
  "flo_mod",
  "flo_divmod",
  "rb_float_pow",
  "rb_float_equal",
  "flo_cmp",
  "rb_float_gt",
  "flo_ge",
  "flo_lt",
  "flo_le",
  "rb_float_eql",
  "flo_hash",
  "rb_float_abs",
  "flo_zero_p",
  "flo_to_i",
  "flo_floor",
  "flo_ceil",
  "flo_round",
  "flo_truncate",
  "flo_is_nan_p",
  "rb_flo_is_infinite_p",
  "rb_flo_is_finite_p",
  "flo_next_float",
  "flo_prev_float",
  "flo_positive_p",
  "flo_negative_p",
  "rb_int_coerce",
 
  "rb_ary_s_create",
  "rb_ary_s_try_convert",
  "rb_ary_initialize",
  "rb_ary_replace",
  "rb_ary_inspect",
  "rb_ary_to_a",
  "rb_ary_to_h",
  "rb_ary_equal",
  "rb_ary_eql",
  "rb_ary_hash",
  "rb_ary_aref",
  "rb_ary_aset",
  "rb_ary_at",
  "rb_ary_fetch",
  "rb_ary_first",
  "rb_ary_last",
  "rb_ary_concat_multi",
  "rb_ary_union_multi",
  "rb_ary_difference_multi",
  "rb_ary_intersection_multi",
  "rb_ary_push",
  "rb_ary_push_m",
  "rb_ary_pop_m",
  "rb_ary_shift_m",
  "rb_ary_unshift_m",
  "rb_ary_insert",
  "rb_ary_each",
  "rb_ary_each_index",
  "rb_ary_reverse_each",
  "rb_ary_length",
  "rb_ary_empty_p",
  "rb_ary_index",
  "rb_ary_rindex",
  "rb_ary_join_m",
  "rb_ary_reverse_m",
  "rb_ary_reverse_bang",
  "rb_ary_rotate_m",
  "rb_ary_rotate_bang",
  "rb_ary_sort",
  "rb_ary_sort_bang",
  "rb_ary_sort_by_bang",
  "rb_ary_collect",
  "rb_ary_collect_bang",
  "rb_ary_select",
  "rb_ary_select_bang",
  "rb_ary_keep_if",
  "rb_ary_values_at",
  "rb_ary_delete",
  "rb_ary_delete_at_m",
  "rb_ary_delete_if",
  "rb_ary_reject",
  "rb_ary_reject_bang",
  "rb_ary_zip",
  "rb_ary_transpose",
  "rb_ary_clear",
  "rb_ary_fill",
  "rb_ary_includes",
  "rb_ary_cmp",
  "rb_ary_slice_bang",
  "rb_ary_assoc",
  "rb_ary_rassoc",
  "rb_ary_plus",
  "rb_ary_times",
  "rb_ary_diff",
  "rb_ary_and",
  "rb_ary_or",
  "rb_ary_max",
  "rb_ary_min",
  "rb_ary_minmax",
  "rb_ary_uniq",
  "rb_ary_uniq_bang",
  "rb_ary_compact",
  "rb_ary_compact_bang",
  "rb_ary_flatten",
  "rb_ary_flatten_bang",
  "rb_ary_count",
  "rb_ary_cycle",
  "rb_ary_permutation",
  "rb_ary_combination",
  "rb_ary_repeated_permutation",
  "rb_ary_repeated_combination",
  "rb_ary_product",
  "rb_ary_take",
  "rb_ary_take_while",
  "rb_ary_drop",
  "rb_ary_drop_while",
  "rb_ary_bsearch",
  "rb_ary_bsearch_index",
  "rb_ary_any_p",
  "rb_ary_all_p",
  "rb_ary_none_p",
  "rb_ary_one_p",
  "rb_ary_dig",
  "rb_ary_sum",
  "rb_hash_s_create",
  "rb_hash_s_try_convert",
  "rb_hash_initialize",
  "rb_hash_replace",
  "rb_hash_rehash",
  "rb_hash_to_h",
  "rb_hash_to_a",
  "rb_hash_inspect",
  "rb_hash_to_proc",
  "rb_hash_equal",
  "rb_hash_aref",
  "rb_hash_hash",
  "rb_hash_eql",
  "rb_hash_fetch_m",
  "rb_hash_aset",
  "rb_hash_default",
  "rb_hash_set_default",
  "rb_hash_default_proc",
  "rb_hash_set_default_proc",
  "rb_hash_key",
  "rb_hash_size",
  "rb_hash_empty_p",
  "rb_hash_each_value",
  "rb_hash_each_key",
  "rb_hash_each_pair",
  "rb_hash_transform_keys",
  "rb_hash_transform_keys_bang",
  "rb_hash_transform_values",
  "rb_hash_transform_values_bang",
  "rb_hash_keys",
  "rb_hash_values",
  "rb_hash_values_at",
  "rb_hash_fetch_values",
  "rb_hash_shift",
  "rb_hash_delete_m",
  "rb_hash_delete_if",
  "rb_hash_keep_if",
  "rb_hash_select",
  "rb_hash_select_bang",
  "rb_hash_reject",
  "rb_hash_reject_bang",
  "rb_hash_slice",
  "rb_hash_except",
  "rb_hash_clear",
  "rb_hash_invert",
  "rb_hash_update",
  "rb_hash_merge",
  "rb_hash_assoc",
  "rb_hash_rassoc",
  "rb_hash_flatten",
  "rb_hash_compact",
  "rb_hash_compact_bang",
  "rb_hash_has_key",
  "rb_hash_has_value",
  "rb_hash_compare_by_id",
  "rb_hash_compare_by_id_p",
  "rb_hash_any_p",
  "rb_hash_dig",
  "rb_hash_le",
  "rb_hash_lt",
  "rb_hash_ge",
  "rb_hash_gt",
  "rb_hash_s_ruby2_keywords_hash_p",
  "rb_hash_s_ruby2_keywords_hash",
  "rb_f_getenv",
  "env_fetch",
  "env_aset_m",
  "env_each_pair",
  "env_each_key",
  "env_each_value",
  "env_delete_m",
  "env_delete_if",
  "env_keep_if",
  "env_slice",
  "env_except",
  "env_clear",
  "env_reject",
  "env_reject_bang",
  "env_select",
  "env_select_bang",
  "env_shift",
  "env_freeze",
  "env_invert",
  "env_replace",
  "env_update",
  "env_inspect",
  "env_none",
  "env_to_a",
  "env_to_s",
  "env_key",
  "env_size",
  "env_empty_p",
  "env_f_keys",
  "env_f_values",
  "env_values_at",
  "env_has_key",
  "env_has_value",
  "env_f_to_hash",
  "env_to_h",
  "env_assoc",
  "env_rassoc",
  "rb_struct_s_def",
  "rb_struct_initialize_m",
  "rb_struct_init_copy",
  "rb_struct_equal",
  "rb_struct_eql",
  "rb_struct_hash",
  "rb_struct_inspect",
  "rb_struct_to_a",
  "rb_struct_to_h",
  "rb_struct_size",
  "rb_struct_each",
  "rb_struct_each_pair",
  "rb_struct_aref",
  "rb_struct_aset",
  "rb_struct_select",
  "rb_struct_values_at",
  "rb_struct_members_m",
  "rb_struct_dig",
  "rb_struct_deconstruct_keys",
  "rb_reg_s_quote",
  "rb_reg_s_union_m",
  "rb_reg_s_last_match",
  "rb_reg_s_try_convert",
  "rb_reg_initialize_m",
  "rb_reg_init_copy",
  "rb_reg_hash",
  "rb_reg_equal",
  "rb_reg_match",
  "rb_reg_eqq",
  "rb_reg_match2",
  "rb_reg_match_m",
  "rb_reg_match_m_p",
  "rb_reg_to_s",
  "rb_reg_inspect",
  "rb_reg_source",
  "rb_reg_casefold_p",
  "rb_reg_options_m",
  "rb_reg_fixed_encoding_p",
  "rb_reg_names",
  "rb_reg_named_captures",
  "match_init_copy",
  "match_regexp",
  "match_names",
  "match_size",
  "match_offset",
  "match_begin",
  "match_end",
  "match_to_a",
  "match_aref",
  "match_captures",
  "match_named_captures",
  "match_values_at",
  "rb_reg_match_pre",
  "rb_reg_match_post",
  "match_to_s",
  "match_inspect",
  "match_string",
  "match_hash",
  "match_equal",
  "str_encode",
  "str_encode_bang",
  "econv_s_asciicompat_encoding",
  "econv_s_search_convpath",
  "econv_init",
  "econv_inspect",
  "econv_convpath",
  "econv_source_encoding",
  "econv_destination_encoding",
  "econv_primitive_convert",
  "econv_convert",
  "econv_finish",
  "econv_primitive_errinfo",
  "econv_insert_output",
  "econv_putback",
  "econv_last_error",
  "econv_get_replacement",
  "econv_set_replacement",
  "econv_equal",
  "ecerr_source_encoding_name",
  "ecerr_destination_encoding_name",
  "ecerr_source_encoding",
  "ecerr_destination_encoding",
  "ecerr_error_char",
  "ecerr_error_bytes",
  "ecerr_readagain_bytes",
  "ecerr_incomplete_input",
  "marshal_dump",
  "marshal_load",
  "range_initialize",
  "range_initialize_copy",
  "range_eq",
  "range_eqq",
  "range_eql",
  "range_hash",
  "range_each",
  "range_step",
  "range_percent_step",
  "range_bsearch",
  "range_begin",
  "range_end",
  "range_first",
  "range_last",
  "range_min",
  "range_max",
  "range_minmax",
  "range_size",
  "range_to_a",
  "range_to_s",
  "range_inspect",
  "range_exclude_end_p",
  "range_include",
  "range_cover",
  "range_count",
  "rb_f_syscall",
  "rb_f_open",
  "rb_f_printf",
  "rb_f_print",
  "rb_f_putc",
  "rb_f_puts",
  "rb_f_gets",
  "rb_f_readline",
  "rb_f_select",
  "rb_f_readlines",
  "rb_f_backquote",
  "rb_f_p",
  "rb_obj_display",
  "rb_io_s_new",
  "rb_io_s_open",
  "rb_io_s_sysopen",
  "rb_io_s_for_fd",
  "rb_io_s_popen",
  "rb_io_s_foreach",
  "rb_io_s_readlines",
  "rb_io_s_read",
  "rb_io_s_binread",
  "rb_io_s_write",
  "rb_io_s_binwrite",
  "rb_io_s_pipe",
  "rb_io_s_try_convert",
  "rb_io_s_copy_stream",
  "rb_io_initialize",
  "rb_io_init_copy",
  "rb_io_reopen",
  "rb_io_print",
  "rb_io_putc",
  "rb_io_puts",
  "rb_io_printf",
  "rb_io_each_line",
  "rb_io_each_byte",
  "rb_io_each_char",
  "rb_io_each_codepoint",
  "rb_io_syswrite",
  "rb_io_sysread",
  "rb_io_pread",
  "rb_io_pwrite",
  "rb_io_fileno",
  "rb_io_fsync",
  "rb_io_fdatasync",
  "rb_io_sync",
  "rb_io_set_sync",
  "rb_io_lineno",
  "rb_io_set_lineno",
  "rb_io_readlines",
  "io_readpartial",
  "io_read",
  "io_write_m",
  "rb_io_gets_m",
  "rb_io_readline",
  "rb_io_getc",
  "rb_io_getbyte",
  "rb_io_readchar",
  "rb_io_readbyte",
  "rb_io_ungetbyte",
  "rb_io_ungetc",
  "rb_io_addstr",
  "rb_io_flush",
  "rb_io_tell",
  "rb_io_seek_m",
  "rb_io_rewind",
  "rb_io_set_pos",
  "rb_io_eof",
  "rb_io_close_on_exec_p",
  "rb_io_set_close_on_exec",
  "rb_io_close_m",
  "rb_io_closed",
  "rb_io_close_read",
  "rb_io_close_write",
  "rb_io_isatty",
  "rb_io_binmode_m",
  "rb_io_binmode_p",
  "rb_io_sysseek",
  "rb_io_advise",
  "rb_io_ioctl",
  "rb_io_fcntl",
  "rb_io_pid",
  "rb_io_inspect",
  "rb_io_external_encoding",
  "rb_io_internal_encoding",
  "rb_io_set_encoding",
  "rb_io_set_encoding_by_bom",
  "rb_io_autoclose_p",
  "rb_io_set_autoclose",
  "argf_initialize",
  "argf_initialize_copy",
  "argf_to_s",
  "argf_argv",
  "argf_fileno",
  "argf_to_io",
  "argf_write_io",
  "argf_each_line",
  "argf_each_byte",
  "argf_each_char",
  "argf_each_codepoint",
  "argf_read",
  "argf_readpartial",
  "argf_read_nonblock",
  "argf_readlines",
  "argf_gets",
  "argf_readline",
  "argf_getc",
  "argf_getbyte",
  "argf_readchar",
  "argf_readbyte",
  "argf_tell",
  "argf_seek_m",
  "argf_rewind",
  "argf_set_pos",
  "argf_eof",
  "argf_binmode_m",
  "argf_binmode_p",
  "argf_write",
  "argf_filename",
  "argf_file",
  "argf_skip",
  "argf_close_m",
  "argf_closed",
  "argf_lineno",
  "argf_set_lineno",
  "argf_inplace_mode_get",
  "argf_inplace_mode_set",
  "argf_external_encoding",
  "argf_internal_encoding",
  "argf_set_encoding",
  "rb_file_directory_p",
  "rb_file_exist_p",
  "rb_file_exists_p",
  "rb_file_readable_p",
  "rb_file_readable_real_p",
  "rb_file_world_readable_p",
  "rb_file_writable_p",
  "rb_file_writable_real_p",
  "rb_file_world_writable_p",
  "rb_file_executable_p",
  "rb_file_executable_real_p",
  "rb_file_file_p",
  "rb_file_zero_p",
  "rb_file_size_p",
  "rb_file_s_size",
  "rb_file_owned_p",
  "rb_file_grpowned_p",
  "rb_file_pipe_p",
  "rb_file_symlink_p",
  "rb_file_socket_p",
  "rb_file_blockdev_p",
  "rb_file_chardev_p",
  "rb_file_suid_p",
  "rb_file_sgid_p",
  "rb_file_sticky_p",
  "rb_file_identical_p",
  "rb_file_s_stat",
  "rb_file_s_lstat",
  "rb_file_s_ftype",
  "rb_file_s_atime",
  "rb_file_s_mtime",
  "rb_file_s_ctime",
  "rb_file_s_birthtime",
  "rb_file_s_utime",
  "rb_file_s_chmod",
  "rb_file_s_chown",
  "rb_f_notimplement",
  "rb_file_s_lchown",
  "rb_file_s_lutime",
  "rb_file_s_link",
  "rb_file_s_symlink",
  "rb_file_s_readlink",
  "rb_file_s_unlink",
  "rb_file_s_rename",
  "rb_file_s_umask",
  "rb_file_s_truncate",
  "rb_file_s_mkfifo",
  "s_expand_path",
  "s_absolute_path",
  "s_absolute_path_p",
  "rb_file_s_realpath",
  "rb_file_s_realdirpath",
  "rb_file_s_basename",
  "rb_file_s_dirname",
  "rb_file_s_extname",
  "rb_file_s_path",
  "rb_file_s_split",
  "rb_file_s_join",
  "rb_io_stat",
  "rb_file_lstat",
  "rb_file_atime",
  "rb_file_mtime",
  "rb_file_ctime",
  "rb_file_birthtime",
  "rb_file_size",
  "rb_file_chmod",
  "rb_file_chown",
  "rb_file_truncate",
  "rb_file_flock",
  "rb_file_path",
  "rb_f_test",
  "rb_stat_init",
  "rb_stat_init_copy",
  "rb_stat_cmp",
  "rb_stat_dev",
  "rb_stat_dev_major",
  "rb_stat_dev_minor",
  "rb_stat_ino",
  "rb_stat_mode",
  "rb_stat_nlink",
  "rb_stat_uid",
  "rb_stat_gid",
  "rb_stat_rdev",
  "rb_stat_rdev_major",
  "rb_stat_rdev_minor",
  "rb_stat_size",
  "rb_stat_blksize",
  "rb_stat_blocks",
  "rb_stat_atime",
  "rb_stat_mtime",
  "rb_stat_ctime",
  "rb_stat_inspect",
  "rb_stat_ftype",
  "rb_stat_d",
  "rb_stat_r",
  "rb_stat_R",
  "rb_stat_wr",
  "rb_stat_w",
  "rb_stat_W",
  "rb_stat_ww",
  "rb_stat_x",
  "rb_stat_X",
  "rb_stat_f",
  "rb_stat_z",
  "rb_stat_s",
  "rb_stat_owned",
  "rb_stat_grpowned",
  "rb_stat_p",
  "rb_stat_l",
  "rb_stat_S",
  "rb_stat_b",
  "rb_stat_c",
  "rb_stat_suid",
  "rb_stat_sgid",
  "rb_stat_sticky",
  "rb_file_initialize",
  "dir_foreach",
  "dir_entries",
  "dir_s_each_child",
  "dir_s_children",
  "dir_fileno",
  "dir_path",
  "dir_inspect",
  "dir_read",
  "dir_each",
  "dir_each_child_m",
  "dir_collect_children",
  "dir_rewind",
  "dir_tell",
  "dir_seek",
  "dir_set_pos",
  "dir_close",
  "dir_s_chdir",
  "dir_s_getwd",
  "dir_s_chroot",
  "dir_s_mkdir",
  "dir_s_rmdir",
  "dir_s_home",
  "rb_dir_exists_p",
  "rb_dir_s_empty_p",
  "file_s_fnmatch",
  "time_s_now",
  "time_s_at",
  "time_s_mkutc",
  "time_s_mktime",
  "time_to_i",
  "time_to_f",
  "time_to_r",
  "time_cmp",
  "time_eql",
  "time_hash",
  "time_init",
  "time_init_copy",
  "time_localtime_m",
  "time_gmtime",
  "time_getlocaltime",
  "time_getgmtime",
  "time_asctime",
  "time_to_s",
  "time_inspect",
  "time_to_a",
  "time_plus",
  "time_minus",
  "time_round",
  "time_floor",
  "time_ceil",
  "time_sec",
  "time_min",
  "time_hour",
  "time_mday",
  "time_mon",
  "time_year",
  "time_wday",
  "time_yday",
  "time_isdst",
  "time_zone",
  "rb_time_utc_offset",
  "time_utc_p",
  "time_sunday",
  "time_monday",
  "time_tuesday",
  "time_wednesday",
  "time_thursday",
  "time_friday",
  "time_saturday",
  "time_usec",
  "time_nsec",
  "time_subsec",
  "time_strftime",
  "tm_plus",
  "tm_minus",
  "tm_initialize",
  "tm_to_time",
  "tm_from_time",
  "rb_f_srand",
  "rb_f_rand",
  "random_init",
  "random_rand",
  "random_bytes",
  "random_get_seed",
  "rand_mt_copy",
  "rand_mt_equal",
  "random_s_rand",
  "random_s_bytes",
  "random_s_seed",
  "random_seed",
  "random_raw_seed",
  "rand_random_number",
  "sig_trap",
  "sig_list",
  "sig_signame",
  "esignal_init",
  "esignal_signo",
  "interrupt_init",
  "rb_resolve_feature_path",
  "rb_f_load",
  "rb_f_require",
  "rb_f_require_relative",
  "rb_mod_autoload",
  "rb_mod_autoload_p",
  "rb_f_autoload",
  "rb_f_autoload_p",
  "rb_proc_s_new",
  "proc_arity",
  "proc_clone",
  "rb_proc_dup",
  "proc_hash",
  "proc_to_s",
  "rb_proc_lambda_p",
  "proc_binding",
  "proc_curry",
  "proc_compose_to_left",
  "proc_compose_to_right",
  "proc_eq",
  "rb_proc_location",
  "rb_proc_parameters",
  "proc_ruby2_keywords",
  "localjump_xvalue",
  "localjump_reason",
  "f_proc",
  "f_lambda",
  "method_eq",
  "method_hash",
  "method_clone",
  "rb_method_call_pass_called_kw",
  "rb_method_curry",
  "rb_method_compose_to_left",
  "rb_method_compose_to_right",
  "method_arity_m",
  "method_inspect",
  "method_to_proc",
  "method_receiver",
  "method_name",
  "method_original_name",
  "method_owner",
  "method_unbind",
  "rb_method_location",
  "rb_method_parameters",
  "method_super_method",
  "rb_obj_method",
  "rb_obj_public_method",
  "rb_obj_singleton_method",
  "umethod_bind",
  "umethod_bind_call",
  "rb_mod_instance_method",
  "rb_mod_public_instance_method",
  "rb_mod_define_method",
  "rb_obj_define_method",
  "binding_clone",
  "binding_dup",
  "bind_eval",
  "bind_local_variables",
  "bind_local_variable_get",
  "bind_local_variable_set",
  "bind_local_variable_defined_p",
  "bind_receiver",
  "bind_location",
  "rb_f_binding",
  "math_atan2",
  "math_cos",
  "math_sin",
  "math_tan",
  "math_acos",
  "math_asin",
  "math_atan",
  "math_cosh",
  "math_sinh",
  "math_tanh",
  "math_acosh",
  "math_asinh",
  "math_atanh",
  "math_exp",
  "math_log",
  "math_log2",
  "math_log10",
  "math_sqrt",
  "math_cbrt",
  "math_frexp",
  "math_ldexp",
  "math_hypot",
  "math_erf",
  "math_erfc",
  "math_gamma",
  "math_lgamma",
  "gc_profile_enable_get",
  "gc_profile_enable",
  "gc_profile_record_get",
  "gc_profile_disable",
  "gc_profile_clear",
  "gc_profile_result",
  "gc_profile_report",
  "gc_profile_total_time",
  "os_each_obj",
  "define_final",
  "undefine_final",
  "os_id2ref",
  "rb_obj_id",
  "count_objects",
  "wmap_aset",
  "wmap_aref",
  "wmap_has_key",
  "wmap_inspect",
  "wmap_each",
  "wmap_each_key",
  "wmap_each_value",
  "wmap_keys",
  "wmap_values",
  "wmap_size",
  "gc_verify_internal_consistency_m",
  "gc_verify_transient_heap_internal_consistency",
  "obj_to_enum",
  "enumerator_initialize",
  "enumerator_init_copy",
  "enumerator_each",
  "enumerator_each_with_index",
  "enumerator_with_object",
  "enumerator_with_index",
  "enumerator_next_values",
  "enumerator_peek_values_m",
  "enumerator_next",
  "enumerator_peek",
  "enumerator_feed",
  "enumerator_rewind",
  "enumerator_inspect",
  "enumerator_size",
  "enumerator_plus",
  "enum_chain",
  "enumerable_lazy",
  "lazy_initialize",
  "lazy_to_enum",
  "lazy_eager",
  "lazy_map",
  "lazy_flat_map",
  "lazy_select",
  "lazy_filter_map",
  "lazy_reject",
  "lazy_grep",
  "lazy_grep_v",
  "lazy_zip",
  "lazy_take",
  "lazy_take_while",
  "lazy_drop",
  "lazy_drop_while",
  "lazy_super",
  "lazy_uniq",
  "lazy_with_index",
  "stop_result",
  "generator_initialize",
  "generator_init_copy",
  "generator_each",
  "yielder_initialize",
  "yielder_yield",
  "yielder_yield_push",
  "yielder_to_proc",
  "producer_each",
  "enumerator_s_produce",
  "enum_chain_initialize",
  "enum_chain_init_copy",
  "enum_chain_each",
  "enum_chain_size",
  "enum_chain_rewind",
  "enum_chain_inspect",
  "arith_seq_begin",
  "arith_seq_end",
  "arith_seq_exclude_end",
  "arith_seq_step",
  "arith_seq_first",
  "arith_seq_last",
  "arith_seq_inspect",
  "arith_seq_eq",
  "arith_seq_hash",
  "arith_seq_each",
  "arith_seq_size",
  "ractor_moved_missing",
  "vm_stat",
  "m_core_make_shareable",
  "m_core_make_shareable_copy",
  "m_core_ensure_shareable",
  "mjit_enabled_p",
  "mjit_pause_m",
  "mjit_resume_m",
  "location_lineno_m",
  "location_label_m",
  "location_base_label_m",
  "location_path_m",
  "location_absolute_path_m",
  "location_to_str_m",
  "location_inspect_m",
  "rb_f_caller",
  "rb_f_caller_locations",
  "iseqw_inspect",
  "iseqw_disasm",
  "iseqw_to_a",
  "iseqw_eval",
  "iseqw_to_binary",
  "iseqw_s_load_from_binary",
  "iseqw_s_load_from_binary_extra_data",
  "iseqw_path",
  "iseqw_absolute_path",
  "iseqw_label",
  "iseqw_base_label",
  "iseqw_first_lineno",
  "iseqw_trace_points",
  "iseqw_each_child",
  "iseqw_s_compile",
  "iseqw_s_compile_file",
  "iseqw_s_compile_option_get",
  "iseqw_s_compile_option_set",
  "iseqw_s_disasm",
  "iseqw_s_of",
  "thread_s_new",
  "thread_start",
  "rb_thread_s_main",
  "thread_s_current",
  "thread_stop",
  "rb_thread_s_kill",
  "rb_thread_exit",
  "thread_s_pass",
  "thread_list",
  "rb_thread_s_abort_exc",
  "rb_thread_s_abort_exc_set",
  "rb_thread_s_report_exc",
  "rb_thread_s_report_exc_set",
  "rb_thread_s_ignore_deadlock",
  "rb_thread_s_ignore_deadlock_set",
  "rb_thread_s_handle_interrupt",
  "rb_thread_s_pending_interrupt_p",
  "rb_thread_pending_interrupt_p",
  "thread_initialize",
  "thread_raise_m",
  "thread_join_m",
  "thread_value",
  "rb_thread_kill",
  "rb_thread_run",
  "rb_thread_wakeup",
  "rb_thread_aref",
  "rb_thread_aset",
  "rb_thread_fetch",
  "rb_thread_key_p",
  "rb_thread_keys",
  "rb_thread_priority",
  "rb_thread_priority_set",
  "rb_thread_status",
  "rb_thread_variable_get",
  "rb_thread_variable_set",
  "rb_thread_variables",
  "rb_thread_variable_p",
  "rb_thread_alive_p",
  "rb_thread_stop_p",
  "rb_thread_abort_exc",
  "rb_thread_abort_exc_set",
  "rb_thread_report_exc",
  "rb_thread_report_exc_set",
  "rb_thread_group",
  "rb_thread_backtrace_m",
  "rb_thread_backtrace_locations_m",
  "rb_thread_getname",
  "rb_thread_setname",
  "rb_thread_to_s",
  "thgroup_list",
  "thgroup_enclose",
  "thgroup_enclosed_p",
  "thgroup_add",
  "rb_mutex_locked_p",
  "rb_mutex_trylock",
  "rb_mutex_lock",
  "rb_mutex_unlock",
  "mutex_sleep",
  "rb_mutex_synchronize_m",
  "rb_mutex_owned_p",
  "rb_queue_initialize",
  "undumpable",
  "rb_queue_close",
  "rb_queue_closed_p",
  "rb_queue_push",
  "rb_queue_pop",
  "rb_queue_empty_p",
  "rb_queue_clear",
  "rb_queue_length",
  "rb_queue_num_waiting",
  "rb_szqueue_initialize",
  "rb_szqueue_close",
  "rb_szqueue_max_get",
  "rb_szqueue_max_set",
  "rb_szqueue_push",
  "rb_szqueue_pop",
  "rb_szqueue_empty_p",
  "rb_szqueue_clear",
  "rb_szqueue_length",
  "rb_szqueue_num_waiting",
  "rb_condvar_initialize",
  "rb_condvar_wait",
  "rb_condvar_signal",
  "rb_condvar_broadcast",
  "f_exec",
  "rb_f_fork",
  "rb_f_exit_bang",
  "rb_f_system",
  "rb_f_spawn",
  "rb_f_sleep",
  "f_exit",
  "f_abort",
  "proc_s_last_status",
  "proc_rb_f_kill",
  "proc_m_wait",
  "proc_wait2",
  "proc_waitall",
  "proc_detach",
  "detach_process_pid",
  "rb_process_status_waitv",
  "pst_equal",
  "pst_bitand",
  "pst_rshift",
  "pst_to_i",
  "pst_to_s",
  "pst_inspect",
  "pst_pid_m",
  "pst_wifstopped",
  "pst_wstopsig",
  "pst_wifsignaled",
  "pst_wtermsig",
  "pst_wifexited",
  "pst_wexitstatus",
  "pst_success_p",
  "pst_wcoredump",
  "proc_get_pid",
  "proc_get_ppid",
  "proc_getpgrp",
  "proc_setpgrp",
  "proc_getpgid",
  "proc_setpgid",
  "proc_getsid",
  "proc_setsid",
  "proc_getpriority",
  "proc_setpriority",
  "proc_getrlimit",
  "proc_setrlimit",
  "proc_getuid",
  "proc_setuid",
  "proc_getgid",
  "proc_setgid",
  "proc_geteuid",
  "proc_seteuid_m",
  "proc_getegid",
  "proc_setegid",
  "proc_initgroups",
  "proc_getgroups",
  "proc_setgroups",
  "proc_getmaxgroups",
  "proc_setmaxgroups",
  "proc_daemon",
  "rb_proc_times",
  "rb_clock_gettime",
  "rb_clock_getres",
  "rb_struct_s_members_m",
  "rb_struct_s_inspect",
  "p_uid_change_privilege",
  "p_gid_change_privilege",
  "p_uid_grant_privilege",
  "p_gid_grant_privilege",
  "p_uid_exchange",
  "p_gid_exchange",
  "p_uid_exchangeable",
  "p_gid_exchangeable",
  "p_uid_have_saved_id",
  "p_gid_have_saved_id",
  "p_uid_switch",
  "p_gid_switch",
  "p_uid_from_name",
  "p_gid_from_name",
  "p_sys_setuid",
  "p_sys_setgid",
  "p_sys_seteuid",
  "p_sys_setegid",
  "p_sys_setreuid",
  "p_sys_setregid",
  "p_sys_setresuid",
  "p_sys_setresgid",
  "rb_fiber_s_yield",
  "rb_fiber_initialize",
  "rb_fiber_blocking_p",
  "rb_fiber_m_resume",
  "rb_fiber_raise",
  "rb_fiber_backtrace",
  "rb_fiber_backtrace_locations",
  "fiber_to_s",
  "rb_f_fiber_blocking_p",
  "rb_fiber_scheduler",
  "rb_fiber_set_scheduler",
  "rb_f_fiber",
  "nurat_f_rational",
  "nurat_numerator",
  "nurat_denominator",
  "rb_rational_uminus",
  "rb_rational_plus",
  "rb_rational_minus",
  "rb_rational_mul",
  "rb_rational_div",
  "nurat_fdiv",
  "rb_rational_pow",
  "rb_rational_cmp",
  "nurat_eqeq_p",
  "nurat_coerce",
  "nurat_positive_p",
  "nurat_negative_p",
  "rb_rational_abs",
  "nurat_floor_n",
  "nurat_ceil_n",
  "nurat_truncate_n",
  "nurat_round_n",
  "nurat_truncate",
  "nurat_to_f",
  "nurat_rationalize",
  "nurat_hash",
  "nurat_to_s",
  "nurat_inspect",
  "rb_gcd",
  "rb_lcm",
  "rb_gcdlcm",
  "numeric_numerator",
  "numeric_denominator",
  "rb_numeric_quo",
  "integer_denominator",
  "rb_float_numerator",
  "rb_float_denominator",
  "nilclass_to_r",
  "nilclass_rationalize",
  "integer_to_r",
  "integer_rationalize",
  "float_to_r",
  "float_rationalize",
  "string_to_r",
  "nucomp_s_new",
  "nucomp_s_polar",
  "nucomp_f_complex",
  "rb_complex_real",
  "rb_complex_imag",
  "rb_complex_uminus",
  "rb_complex_plus",
  "rb_complex_minus",
  "rb_complex_mul",
  "rb_complex_div",
  "nucomp_fdiv",
  "rb_complex_pow",
  "nucomp_eqeq_p",
  "nucomp_cmp",
  "nucomp_coerce",
  "rb_complex_abs",
  "nucomp_abs2",
  "rb_complex_arg",
  "nucomp_rect",
  "nucomp_polar",
  "rb_complex_conjugate",
  "nucomp_numerator",
  "nucomp_denominator",
  "nucomp_hash",
  "nucomp_eql_p",
  "nucomp_to_s",
  "nucomp_inspect",
  "rb_complex_finite_p",
  "rb_complex_infinite_p",
  "nucomp_to_i",
  "nucomp_to_f",
  "nucomp_to_r",
  "nucomp_rationalize",
  "nilclass_to_c",
  "numeric_to_c",
  "string_to_c",
  "numeric_imag",
  "numeric_abs2",
  "numeric_arg",
  "numeric_rect",
  "numeric_polar",
  "float_arg",
  "set_trace_func",
  "thread_set_trace_func_m",
  "thread_add_trace_func_m",
  "proc_argv0",
  "proc_setproctitle",
  */
]);

// function log_pc(insn) { log("[" + insn + "] pc: " + vm.GET_PC()) }
function log_pc(insn) {}

function return_callback_wrapper(func, insn) {
  return function(args) {
    let cb = vm.return_callback;
    // log(">> vm.return_callback: " + vm.return_callback)
    // log(">> vm.last_insn: " + JSON.stringify(vm.last_insn))
    if (cb != null) {
      vm.return_callback = null;

      let last_insn = vm.last_insn;
      if (last_insn != null) {
        vm.last_insn = null;
        if (insn == 'opt_send_without_block') {
        // handling for CALL_SIMPLE_METHOD
          let has_simple = last_insn[3];
          if (has_simple) {
            // check sp first (note: some will always have the same, like opt_nil_p)
            let sp = vm.GET_SP();
            let orig_sp = last_insn[1];
            let expected_sp = last_insn[2];
            // log(">> sp: " + sp)
            // log(">> orig_sp: " + orig_sp)
            // log(">> expected_sp: " + expected_sp)
            if (!sp.equals(expected_sp) && sp.equals(orig_sp)) {
              // we are pretty much certain to have a match
              let last_insn_name = last_insn[0];
              log(">> " + last_insn_name + " -> CALL_SIMPLE_METHOD()");
              log_pc(insn)
              func(args);
              return;
            } else if (orig_sp.equals(expected_sp)) {
              // edge case for insns like opt_nil_p
              // defer to opt_send_without_block hook to compare operator against mid
              log_pc(insn)
              func(args, last_insn, cb);
              return;
            } else {
              let check_fn = last_insn[5];
              if (check_fn != null) {
                if (check_fn()) {
                  let last_insn_name = last_insn[0];
                  log(">> " + last_insn_name + " -> CALL_SIMPLE_METHOD()");
                  log_pc(insn)
                  func(args);
                  return;
                }
              }
            }
          }
        }
      }
      cb();
    }
    log_pc(insn)
    func(args);
  }
}

class Hooks {
  constructor (parameters) {
    this.tracer_interceptors = {}
    this.is_tracing = false;
    this.cfunc_hooks = {};
    this.cfunc_hooks_metadatas = {}
    r.hooks = this;
    this.gc_status = null;
    this.trace_symbols = [];
    if (parameters.traceSymbols !== undefined) {
      this.trace_symbols = parameters.traceSymbols.split(",");
    }

    // enable/disable hooks
    let self = this;

    this.rb_vm_call0_ptr = r.sym_to_addr_map['rb_vm_call0'].address;
    // ruby 2.6
    //   MJIT_FUNC_EXPORTED VALUE rb_vm_call0(rb_execution_context_t *ec, VALUE recv, ID id, int argc, const VALUE *argv, const rb_callable_method_entry_t *me)
    // ruby 2.7-3.0
    //   MJIT_FUNC_EXPORTED VALUE rb_vm_call0(rb_execution_context_t *ec, VALUE recv, ID id, int argc, const VALUE *argv, const rb_callable_method_entry_t *me, int kw_splat)
    switch (vm.ruby_version) {
      case 26: {
        this.rb_vm_call0_sig = ['pointer', VALUE, ID, 'int', 'pointer', 'pointer'];
        break;
      }
      case 27:
      case 30:
      case 31:
      default: {
        this.rb_vm_call0_sig = ['pointer', VALUE, ID, 'int', 'pointer', 'pointer', 'int'];
      }
    }
    this._rb_vm_call0 = new NativeFunction(this.rb_vm_call0_ptr, VALUE, this.rb_vm_call0_sig);

    for (let s of ['rb_tracepoint_enable', 'rb_thread_add_event_hook2', 'rb_add_event_hook2']) {
      Interceptor.attach(r.libruby.getExportByName(s), {
        onLeave: function(retval) {
          try {
            self.trace()
          } catch (e) {
            log("Error [" + s + "]: " + String(e))
          }
        }
      });
    }
    
    for (let s of ['rb_hook_list_connect_tracepoint', 'tracepoint_enable_m']) {
      Interceptor.attach(r.sym_to_addr_map[s].address, {
        onLeave: function(retval) {
          try {
            self.trace()
          } catch(e) {
            log("Error [" + s + "]: " + String(e))
          }
        }
      });
    }

    for (let s of this.trace_symbols) {
      Interceptor.attach(r.sym_to_addr_map[s].address, {
        onLeave: function(retval) {
          try {
            self.trace()
          } catch(e) {
            log("Error [" + s + "]: " + String(e))
          }
        }
      });
    }

    for (let s of ['rb_tracepoint_disable']) {
      Interceptor.attach(r.libruby.getExportByName(s), function(args) {
        try {
          self.untrace();
        } catch (e) {
          log("Error [rb_tracepoint_disable]: " + String(e))
        }
      });
    }
    
  }

  trace() {
    //note: it currently appears that we can run into a situation w/ the
    //      following error from newobj_slowpath():
    //        "object allocation during garbage collection phase"
    //      we should try to check what part of our runtime hooks are tripping
    //      the relevant checks and if we can selectively disable gc for
    //      ourselves

    //disable gc
    this.gc_status = r.rb_gc_disable()

    if (Object.keys(this.tracer_interceptors).length > 0) {
      return;
    }
    this.is_tracing = true;
    this.tracer_interceptors['rb_vm_call_cfunc'] = Interceptor.attach(r.sym_to_addr_map['rb_vm_call_cfunc'].address, trace_rb_vm_call_cfunc);

    // this.tracer_interceptors['rb_ivar_set'] = Interceptor.attach(r.libruby.getExportByName('rb_ivar_set'), function(args) {
    //   let obj = r.rb_inspect2(args[0]);
    //   let id = r.rb_id2name(args[1]).readUtf8String();
    //   log(">> rb_ivar_set: " + obj + ", " + id + ", ...");
    // });

    switch (vm.ruby_version) {
      case 26:
      case 27: {
        this.tracer_interceptors['vm_call_cfunc'] = Interceptor.attach(r.sym_to_addr_map['vm_call_cfunc'].address, trace_vm_call_cfunc(this));
        break;
      }
      case 30:
      case 31:
      default: {
        //note: in ruby 3.0, only the first of each cfunc call is to vm_call_cfunc,
        //      which calls vm_call_cfunc_with_frame directly, but also sets
        //      cc->call_ to vm_call_cfunc_with_frame so that future calls skip
        //      vm_call_cfunc and go directly to vm_call_cfunc_with_frame.
        //      we therefore hook vm_call_cfunc_with_frame instead of vm_call_cfunc
        //      but treat it the same since the function signature is identical
        this.tracer_interceptors['vm_call_cfunc'] = Interceptor.attach(r.sym_to_addr_map['vm_call_cfunc_with_frame'].address, trace_vm_call_cfunc(this));
      }
    }
    
    // this.tracer_interceptors['vm_sendish.constprop.531'] = Interceptor.attach(r.sym_to_addr_map['vm_sendish.constprop.531'].address, function(args) {
    //   log(">> vm_sendish.constprop.531 hit")
    // })

    // this.tracer_interceptors['vm_search_method_slowpath0.isra.477'] = Interceptor.attach(r.sym_to_addr_map['vm_search_method_slowpath0.isra.477'].address, function(args) {
    //   log(">> vm_search_method_slowpath0.isra.477 hit")
    // })

    // this.tracer_interceptors['vm_call_general'] = Interceptor.attach(r.sym_to_addr_map['vm_call_general'].address, function(args) {
    //   log(">> vm_call_general hit")
    // })
    // this.tracer_interceptors['vm_call_method'] = Interceptor.attach(r.sym_to_addr_map['vm_call_method'].address, function(args) {
    //   log(">> vm_call_method hit")
    // })
    
    // note: per https://github.com/frida/frida/issues/166#issuecomment-778093754,
    //       we hook rb_vm_call0 with Interceptor.replace so that our hook on
    //       rb_funcallv gets hit if called directly or indirectly (from libruby)
    //       from our rb_vm_call0 hook.
    let self = this;
    switch (vm.ruby_version) {
      case 26: {
        Interceptor.replace(this._rb_vm_call0, new NativeCallback((ec, recv, id, argc, argv, me) => {
          let log_str = trace_rb_vm_call0([ec, recv, id, ptr(argc), argv, me]);
          let ret = self._rb_vm_call0(ec, recv, id, argc, argv, me);
          if (log_str != null) {
            log(log_str + " -> " + r.dyn_inspect(ret))
          }
          return ret;
        }, VALUE, this.rb_vm_call0_sig));
        break;
      }
      case 27:
      case 30:
      case 31:
      default: {
        Interceptor.replace(this._rb_vm_call0, new NativeCallback((ec, recv, id, argc, argv, me, kw_splat) => {
          let log_str = trace_rb_vm_call0([ec, recv, id, ptr(argc), argv, me, ptr(kw_splat)]);
          let ret = self._rb_vm_call0(ec, recv, id, argc, argv, me, kw_splat);
          if (log_str != null) {
            log(log_str + " -> " + r.dyn_inspect(ret))
          }
          return ret;
        }, VALUE, this.rb_vm_call0_sig));
      }
    }

    if (vm.OPT_INLINE_METHOD_CACHE()) {
      switch (vm.ruby_version) {
        case 27: {
          //note: in ruby 2.7, it looks like the reason vm_call_cfunc seems to be called every time for a cfunc call
          //      is that the caching is not as good as in ruby 3.0, and additionally, even if the caching happens,
          //      it is vm_call_cfunc itself that is the cached function called directly.
          this.tracer_interceptors['vm_search_method_fastpath'] = Interceptor.attach(r.sym_to_addr_map['vm_search_method_fastpath'].address, function(args){
            // log(">> vm_search_method_fastpath hit")
            let cd_p = args[0]
            let klass = args[1]
            let cc_p = vm.native.rb_call_data__cc(cd_p)
            let serial = vm.native.RCLASS_SERIAL(klass)

            let has_class_serial = vm.native.rb_call_cache__has_class_serial(cc_p, serial)
            if (has_class_serial == 1) {
              // log(">> has class serial!")
              let call_p = vm.native.rb_call_cache__call(cc_p)
              if (!call_p.isNull()) {
                let call_s = r.get_func_name(call_p)
                log(">> vm_search_method_fastpath: inline method cache hit, cd->cc->call: " + call_s);

                // if (call_s.startsWith("vm_call_iseq_")) {
                //   return;
                // }
                // if (!(call_p in self.cfunc_hooks_metadatas) && !(call_p in r.rb_define_method_metadatas)) {
                //   log(">> hooking cached func dynamically")
                //   let ci_p = vm.native.rb_call_data__ci(cd_p)
                //   let mid_p = vm.native.rb_call_info__mid(ci_p)
                //   let mid = r.rb_id2name(mid_p).readUtf8String();
                //   log(">> mid: " + mid)
                //   let me_p = vm.native.rb_call_cache__me(cc_p);
                //   let def_p = vm.native.rb_callable_method_entry_t__def(me_p);
                //   let argc = vm.native.rb_method_definition_struct__cfunc__argc(def_p)
                //   let call_info_orig_argc = vm.native.rb_call_info__orig_argc(ci_p);

                //   log(">> argc: " + argc)

                //   let metadata = {
                //     method: {
                //       mid: mid,
                //     },
                //     cfunc: {
                //       func_p: call_p,
                //       func_s: call_s,
                //       def_argc: argc,
                //       rt_argc: call_info_orig_argc
                //     }
                //   };
          
                //   self.cfunc_hooks_metadatas[cfunc_func_p] = metadata
                //   self.hook_cfunc(metadata, true);
                // }

              }
            }/* else {
              log(">> does not have class serial: " + has_class_serial)
            }*/
          })    
          break;
        }
        case 30:
        case 31: //note: likely inlined
        default: {
          if (r.vm_sendish != null) {
            this.tracer_interceptors['vm_sendish'] = Interceptor.attach(r.vm_sendish.address, function(args){
              // log(">> vm_sendish hit")
              let method_explorer = args[4]
              if (!method_explorer.equals(ptr(0x0))) { // 0: mexp_search_method, but it's also a good check for the mjit funcptr variant
                return;
              }
              let reg_cfp = args[1]
              let cd_p = args[2]
              let ci_p = vm.native.rb_call_data__ci(cd_p)
              let cc_p = vm.native.rb_call_data__cc(cd_p)

              let argc = vm.native.rb_callinfo__argc(ci_p)
              //VALUE recv = TOPN(argc);
              let recv = vm.TOPN(argc, null, reg_cfp)

              //CLASS_OF(recv)
              let klass = r.rb_class_of(recv);

              let cached = vm.native.rb_callcache__INLINE_METHOD_CACHE_CHECK(cc_p, klass);
              if (cached == 1) {
                let call_p = vm.native.rb_callcache__call_(cc_p)
                let call_s = r.get_func_name(call_p)
                log(">> vm_sendish: inline method cache hit, cd->cc->call_: " + call_s);
              }
  
            });  
          } else { // we get creative
            //note: there are 4 callers of vm_sendish
            //      * insn send, w/ mexp_search_method
            //      * insn opt_send_without_block, w/ mexp_search_method
            //      * insn invokesuper, w/ mexp_search_super
            //      * insn invokeblock, w/ mexp_search_invokeblock
            //
            //      while there are no symbols for the method_explorer
            //      funcs, we don't actually need to check it if we use
            //      the insns entry points themselves
            //
            //      so we handle this in call_ops
          }
        }
      }
    }

    //note: while rb_iterate itself is exported, rb_lambda_call uses rb_iterate0 directly
    this.tracer_interceptors['rb_iterate0'] = Interceptor.attach(r.sym_to_addr_map['rb_iterate0'].address, trace_rb_iterate0);

    for (let rb_ec_tag_jump of r.rb_ec_tag_jump_list) {
      this.tracer_interceptors[rb_ec_tag_jump.name] = Interceptor.attach(rb_ec_tag_jump.address, trace_rb_ec_tag_jump(rb_ec_tag_jump.name));
    }
    this.tracer_interceptors['rb_throw_obj'] = Interceptor.attach(r.libruby.getExportByName('rb_throw_obj'), trace_rb_throw_obj);

    const call_ops = ["send", "opt_send_without_block", "invokesuper"];

    // let INSTRUCTIONS_SORTED = (()=>{
    //   let insns = Object.entries(vm.INSTRUCTIONS);
    //   insns.sort(function(a, b) {
    //     return a[1].compare(b[1]);
    //   });
    //   return insns;
    // })();

    //console.log(JSON.stringify(INSTRUCTIONS_SORTED))

    for (const [k, v] of Object.entries(vm.INSTRUCTIONS)) {
    //for (let i = 0; i < INSTRUCTIONS_SORTED.length; i++) {
      //const [k, v] = INSTRUCTIONS_SORTED[i];

      try {

        if (k.startsWith("trace_")) {
          continue;
        }

        let insnhook = insnhooks[k];
        if (insnhook !== undefined) {
          if (typeof insnhook == 'function') {            
            this.tracer_interceptors["YARVINSN_" + k] = Interceptor.attach(v, return_callback_wrapper(insnhook, k));
          } else {
            //note: generally, it appears that there is a dangling trace insn
            //      with a JMP at the end. however, we can detect if there isn't
            //      another insn that we can know the start of. I doubt that this
            //      would work reliably on the various platforms and it would
            //      probably break when ruby is compiled w/ other opt ifdefs.
            //
            //      currently, frida is having trouble hooking these native
            //      instructions. it's unclear what is going wrong.
            //      TODO: submit an issue to frida after release.
            //      Example instruction decoded w/ Instruction.parse():
            //        {"address":"0x7f51e3b0d69a","next":"0x7f51e3b0d69d","size":3,"mnemonic":"jmp","opStr":"qword ptr [rbp + 0x18]","operands":[{"type":"mem","value":{"base":"rbp","scale":1,"disp":24},"size":8}],"regsRead":[],"regsWritten":[],"groups":["mode64","jump"]}
            //        Error: unable to intercept function at 0x7f51e3b0d69a; please file a bug
            //
            //      So in the meantime, it might make more sense to hackily
            //      set up return callbacks that are called at the start of
            //      each instruction.
            /*
            if (i == INSTRUCTIONS_SORTED.length-1) {
              console.error("Error [trace]: no next yarv instruction following " + k)
            } else {
              const [nk, nv] = INSTRUCTIONS_SORTED[i+1];
              let curr = v;
              let last = null;
              while (curr < nv) {
                let insn = Instruction.parse(curr);
                if (nv.equals(insn.next)) {
                  last = curr;
                  //console.log(JSON.stringify(insn));
                  break;
                }
                curr = insn.next;
              }
              if (last != null) {
                this.tracer_interceptors["YARVINSN_" + k + "_leave"] = Interceptor.attach(last, insnhook.leave)
              } else {
                console.error("something bad happened w/ " + k)
              }  
            }
            */
            this.tracer_interceptors["YARVINSN_" + k + "_enter"] = Interceptor.attach(v, return_callback_wrapper(insnhook.enter), k)
          }
        } else {
          this.tracer_interceptors["YARVINSN_" + k] = Interceptor.attach(v, return_callback_wrapper(function(args) {
            // log(">> YARVINSN " + k + " hit")
            log(">> " + k)
          }, k));
        }
      } catch (e) {
        console.error("Error [trace]: Failed to instrument YARVINSN " + k + ". " + String(e))
      }
    }

    for (let [k, v] of Object.entries(r.rb_define_method_metadatas)) {
      try {
        // log(">> hooking cfunc " + v.cfunc.func_s + " via rb_define_method_metadatas in hooks.js")
        this.hook_cfunc(v)
      } catch (e) {
        //log("Error [Hooks.trace():rb_define_method_metadatas]: " + String(e))
      }
    }
    for (let [k, v] of Object.entries(r.rb_define_module_function_metadatas)) {
      try {
        // log(">> hooking cfunc " + v.cfunc.func_s + " via rb_define_module_function_metadatas in hooks.js")
        this.hook_cfunc(v)
      } catch (e) {
        //log("Error [Hooks.trace():rb_define_module_function_metadatas]: " + String(e))
      }
    }
    for (let [k, v] of Object.entries(this.cfunc_hooks_metadatas)) {
      try {
        // log(">> hooking cfunc " + v.cfunc.func_s + " via cfunc_hooks_metadatas in hooks.js")
        this.hook_cfunc(v, /*true*/ false)
      } catch (e) {
        //log("Error [Hooks.trace():cfunc_hooks_metadatas]: " + String(e))
      }
    }
  }

  tracing() {
    return this.is_tracing;
  }

  untrace() {
    this.is_tracing = false;
    for(let [k, v] of Object.entries(this.tracer_interceptors)) {
      v.detach();
      delete this.tracer_interceptors[k];
    }
    Interceptor.revert(this.rb_vm_call0_ptr);

    for(let [k, v] of Object.entries(this.cfunc_hooks)) {
      v.detach();
      delete this.cfunc_hooks[k];
    }

    //re-enable gc // 
    if (this.gc_status.equals(r.Qfalse)) {
      this.gc_status = null;
      r.rb_gc_enable()
    }

    //TODO: keep track of functions to hook so that re-enabling can autowire all of them
    //      and hook them separately from keeping track of them
  }
  
  hook_cfunc(metadata, autoremove=false) {
    let cfunc_func_p = metadata.cfunc.func_p;

    if (cfunc_func_p in this.cfunc_hooks) {
      return
    }
    
    let cfunc_func = metadata.cfunc.func_s;
    let cfunc_sym = r.get_sym_name(cfunc_func_p)
    if (unhookables.has(cfunc_sym)) {
      // ignore unhookables for now
      // log(">> skipping unhookable function " + cfunc_func)
      return;
    } else if (cfunc_sym == "<unknown>") {
      //log(">> hook_cfunc: skipping unknown func " + cfunc_func_p)
      // return;
    } else {
      // log(">> hook_cfunc: hooking " + cfunc_sym)
    }

    let autoremove_onEnter = false;
    let autoremove_onLeave = autoremove;
  
    let _self = this;
    let hook = {
      onEnter: function(frida_args) {
        if (r.inspecting) {
          return;
        }
        let def_argc = metadata.cfunc.def_argc;
        let rt_argc = metadata.cfunc.rt_argc;
        try {
          if (def_argc >= 0) {
            let argc;
            if (def_argc != rt_argc && rt_argc != null) {
              // log(">> cfunc def_argc: " + def_argc + " != rt_argc: " + rt_argc)
              argc = rt_argc + 1;
            } else {
              argc = def_argc + 1;
            }
            // let argc = metadata.cfunc.rt_argc;
            let recv = frida_args[0];
            let argv = [];
            for (let i=1; i<argc/*+1*/; i++) {
              argv.push(frida_args[i]);
            }
            // log(">> " + cfunc_sym + " about to static_inspect")
            let recv_inspect = r.static_inspect(recv, false, cfunc_sym);
            if (recv_inspect == null) {
              // log(">> falling back to rb_inspect2")
              try {
                recv_inspect = r.rb_inspect2(recv);
              } catch (e) {
                recv_inspect = "<unknown:" + recv + ">"
              }
            } else if (recv_inspect == -1) {
              recv_inspect = "<unknown:" + recv + ">"
            }

            // log(">> onEnter hook: recv_inspect: " + recv_inspect)
            let argv_inspect = [];
            for (let v of argv) {
              if (v == r.Qnil) {
                argv_inspect.push("nil");
              } else {
                argv_inspect.push(r.rb_inspect2(v));
              }
            }
  
            let argv_inspect_s = "";
            if (argc > 1) {
              //argv_inspect_s = ", " + JSON.stringify(argv_inspect).slice(1,-1);
              argv_inspect_s = ", " + argv_inspect.join(", ");
            }
            this.call_str = metadata.cfunc.func_s + "(" + recv_inspect + argv_inspect_s + ")"
          } else if (def_argc == -1) {
            let argc = frida_args[0];
            let argv_p = frida_args[1];
            let recv = frida_args[2];
  
            let recv_inspect = r.rb_inspect2(recv);
            let argv_inspect = [];
  
            for (let i=0; i < argc; i++) {
              let v = argv_p.add(i*Process.pointerSize).readPointer();
              if (v == r.Qnil) {
                argv_inspect.push("nil");
              } else {
                argv_inspect.push(r.rb_inspect2(v));
              }
            }
  
            let argv_inspect_str = "[" + argv_inspect.join(", ") + "]";
            this.call_str = metadata.cfunc.func_s + "(" + argc + ", " + argv_inspect_str + ", " + recv_inspect + ")"
          } else if (def_argc == -2) {
            //let argc = metadata.cfunc.rt_argc; //unused
            let recv = frida_args[0];
            let args = frida_args[1]; // rb_ary_new4(...)
  
            let recv_inspect = r.rb_inspect2(recv);
            let args_inspect_s = r.rb_inspect2(args);
  
            this.call_str = metadata.cfunc.func_s + "(" + recv_inspect + ", " + args_inspect_s  + ")"
          }
          log(">> cfunc: " + this.call_str)

          if (autoremove_onEnter) {
            _self.cfunc_hooks[cfunc_func_p].detach()
            delete _self.cfunc_hooks[cfunc_func_p]
            delete _self.cfunc_hooks_metadatas[cfunc_func_p]
          }
        } catch(e) {
          // log(">> cfunc: " + metadata.cfunc.func_s + "(def_argc: " + def_argc + ", rt_argc: " + rt_argc + ")");
          log("Error [hook_cfunc::hook.onEnter::" + cfunc_sym + "]: " + String(e))
        }
      },
      onLeave: function(retval) {
        if (r.inspecting) {
          return;
        }
        try {
          if (this.call_str !== undefined) {
            log(">> cfunc: " + this.call_str + " -> " + r.rb_inspect2(retval));
          } else {
            log(">> cfunc: " + metadata.cfunc.func_s + "(...) -> " + r.rb_inspect2(retval));
          }
        } catch (e) {
          log(">> cfunc: " + metadata.cfunc.func_s + "(...) -> ???");
          log("Error [hook_cfunc::hook.onLeave::" + cfunc_sym + "]: " + String(e))
        }
        if (autoremove_onLeave) {
          _self.cfunc_hooks[cfunc_func_p].detach()
          delete _self.cfunc_hooks[cfunc_func_p]
          delete _self.cfunc_hooks_metadatas[cfunc_func_p]
        }
      }
    }
  
    //note: ruby's longjmp exception implementation seems to wreak havoc on
    //      frida's function hooking when it attempts to place
    //      onEnter/onLeave hooks. going forward, it will probably be best to
    //      just maintain a list of at-issue functions and only hook their
    //      first instruction. but for now, let's try a hacky heuristic.
    //
    //      other errors:
    //      * Error: unable to intercept function at 0x7f4f1afa47d0; please file a bug // rb_ary_deconstruct[@0x7f4f1afa47d0](argc: 0) (regardless of attach type)
    try {
      // if (cfunc_sym == "rb_class_new_instance_pass_kw") {
      //   log(">> trace_vm_call_cfunc: bailing on rb_class_new_instance_pass_kw")
      //   return
      // }

      //note: the problem w/ metadata.recv.inspect here is that it's specific
      //      to the vm_call_cfunc recv we were using before, but kind of falls
      //      apart when trying to work w/ rb_define_method. the "problem" is
      //      that, at least for now, there can be issues with certain classes
      //      being initialized. the problem for us is that for things like
      //      Fiber, we currently need to avoid getting a return value out of
      //      it. but Fibers aren't only created from rb_fiber_initialize, but
      //      rb_class_s_new for Fiber.new itself. so instead of using recv,
      //      since it differs, we just don't do return hooks on rb_class_s_new
      //      or rb_fiber_initialize. in the case of the former, it's not like
      //      anything interesting would generally be printed out anyway.
      //
      //note: as i wrote this, it seems like Fiber.new is not being an issue wrt
      //      the errors i was originally seeing. i think the refactor adding
      //      .isNull() to everything in ruby.js may have fixed some of the
      //      issues w/ that/dyn_inspect.
      
      if (cfunc_sym.includes("_raise")) {// || cfunc_sym == "rb_class_s_new" || cfunc_sym == "rb_fiber_initialize" /*|| (metadata.recv.inspect == "Fiber" && metadata.method.mid == "new")*/) {
        //log(">> hook_cfunc: hooking only entry to " + cfunc_func)
        this.cfunc_hooks[cfunc_func_p] = Interceptor.attach(cfunc_func_p, hook.onEnter);
      } else {
        this.cfunc_hooks[cfunc_func_p] = Interceptor.attach(cfunc_func_p, hook);
      }

    } catch (e) {
      if (String(e).includes("please file a bug")) {
        // throw String(e) + " // ruby-trace: failed on " + cfunc_func
        try {
          autoremove_onEnter = autoremove_onLeave;
          this.cfunc_hooks[cfunc_func_p] = Interceptor.attach(cfunc_func_p, hook.onEnter);
          log("Error [hook_cfunc]: failed on " + cfunc_func + ", but hooked entry")
        } catch (e) {
          if (String(e).includes("please file a bug")) {
            throw String(e) + " // ruby-trace: failed on " + cfunc_func
          }
        }
      }
    }
  }
  
}


let singleton = null;

module.exports = function (parameters) {
  if (singleton === null) {
    singleton = new Hooks(parameters);
  }

  return singleton;
}


function trace_rb_vm_call0(args) {
  //note: this seemingly breaks fibers. however, w/o it, fiber execution still
  //      seems to be a problem wrt ec_p. They likely use alternate ec's which
  //      results in our GET_OPERAND/etc implementations failing b/c they're
  //      based on a single ec.
  //
  //TODO 1: figure out (and fix) what in trace_rb_vm_call0 makes Fiber.new fail
  //        - cause: r.dyn_inspect
  //        - why: ???
  //        - fix: ???
  //TODO 2: implement multi ec handling (which we will likely need for ractors)

  //return;
  // ruby 2.6
  //   MJIT_FUNC_EXPORTED VALUE rb_vm_call0(rb_execution_context_t *ec, VALUE recv, ID id, int argc, const VALUE *argv, const rb_callable_method_entry_t *me)
  // ruby 2.7-3.0
  //   MJIT_FUNC_EXPORTED VALUE rb_vm_call0(rb_execution_context_t *ec, VALUE recv, ID id, int argc, const VALUE *argv, const rb_callable_method_entry_t *me, int kw_splat)
  //   // the kw_splat is formed from `int rb_keyword_given_p(void) { return rb_vm_cframe_keyword_p(GET_EC()->cfp); }`
  //   // which is ruby 2.7+ specific

  // log(">>>> trace_rb_vm_call0")
  // return;
  try {
    r.disable_funcall()
    //note: as far as i can tell, there's something about the execution state
    //      of ruby that breaks down if rb_funcallv is called here (probably
    //      at any point in something from vm_eval.c tbh). since rb_inspect
    //      is itself just a wrapper around rb_funcallv :inspect, that ends up
    //      causing some sort of mangling of state and things like
    //      getlocal_WC_0 start returning bad values immediately after.
    //      to prevent this, it seems necessary to use only vanilla ruby c
    //      functions that don't call methods through objects themselves.
    //      we therefore can't use r.rb_inspect, r.ruby_inspect, or r.ruby_to_s
    //
    //      however, while rb_obj_inspect does sort of work, it's very generic.
    //      the more proper solution here is to try to figure out the type and
    //      then use that to pick the right rb_*_inspect c function to call.
    //      due to this, we have this sort of insane set of hooks on
    //      rb_define_method and rb_define_alias that we use to get classes,
    //      class names (where possible), and functions for "inspect" and
    //      "to_s" methods (the latter of which are aliased to "inspect" for
    //      several classes). then in our ruby_init hook (at which point we
    //      know that enough of ruby is initialized to do anything) we
    //      translate the to_s classes to class names and use those to remap
    //      function pointers for inspect based on alias mappings.
    //
    //      interestingly enough, this might have been the issue behind why
    //      tracing the ruby vm from ruby init was causing crashes. after
    //      fixing this, investigate doing full process tracing again.

    let recv_p = args[1];
    let id_p = args[2];
    let argc = args[3]
    let argv_p = args[4]
    //let me_p = args[5]
    //let recv = r.rb_inspect2(r.rb_obj_class(recv_p));
    //let recv_inspect = r.rb_inspect2(recv_p); //note: this line seems to break the stack
    //let recv_inspect = r.ruby_str_to_js_str(r.rb_obj_inspect(recv_p)); // fine, but generic output

    //note: r.dyn_inspect is causing the error for Fiber.new
    let recv_inspect = r.dyn_inspect(recv_p);
    //log("[trace_rb_vm_call0]: " + r.ruby_str_to_js_str(r.dyn_inspect(recv_p)))
    //let object_id = parseInt(r.rb_num2ull(r.rb_obj_id(recv_p)).toString())
    let id = r.rb_id2name(id_p).readUtf8String();

    let argv_inspect = [];
    for (let i=0; i < argc; i++) {
      let v = argv_p.add(i*Process.pointerSize).readPointer();
      if (v == r.Qnil) {
        argv_inspect.push("nil");
      } else {
        argv_inspect.push(r.rb_inspect2(v));
      }
    }

    // if (id == "inherited") { //note(jtd): ?
    //   return;
    // }

    switch (vm.ruby_version) {
      case 26: {
        //pass
        //note: there doesn't seem to be a way to determine if this call has kw_args
        break;
      }
      case 27:
      case 30:
      case 31:
      default: {
        //note: we are forcing args[6] to be a ptr like it would be w/ attach
        //      so we can revert back to attach in the future.
        let kw_splat = args[6].and(0xffffffff);
        if (kw_splat > 0) {
          argv_inspect[argv_inspect.length-1] = "**" + argv_inspect[argv_inspect.length-1];
        }
      }
    }

    let log_str = ">> rb_vm_call0: (" + recv_inspect + ")." + id + "(" + argv_inspect + ")"
    log(log_str);
    return log_str;
  } catch(e) {
    console.error("Error [trace_rb_vm_call0]: " + String(e))
    return null;
  } finally {
    r.enable_funcall()
  }
}

function trace_rb_vm_call_cfunc(args) {
  // ruby 2.6-3.0
  //   VALUE rb_vm_call_cfunc(VALUE recv, VALUE (*func)(VALUE), VALUE arg, VALUE block_handler, VALUE filename)
  try {
    let recv_p = args[0];
    let func_p = args[1];
    let arg_p = args[2];
    //let block_handler_p = args[3];
    let filename_p = args[4];

    let recv_inspect = r.rb_inspect2(recv_p);
    let func_name = r.get_func_name(func_p);
    let arg_inspect = r.rb_inspect2(arg_p);
    let filename = r.rb_inspect2(arg_p);

    log(">> rb_vm_call_cfunc(" + recv_inspect + ", " + func_name + ", ..., " + arg_inspect + ", " + filename + ")")
  } catch(e) {
    console.error("Error [trace_rb_vm_call_cfunc]: " + String(e))
  }
}

let leave = function(name) {
  return function() {
    let val_p = vm.TOPN(0);
    let val_inspect = r.rb_inspect2(val_p);
    log(">> " + name + " -> " + val_inspect);
  };
};




function trace_vm_call_cfunc(hooks) {
  // ruby 2.6
  //   VALUE vm_call_cfunc(rb_execution_context_t *ec, rb_control_frame_t *reg_cfp, struct rb_calling_info *calling, const struct rb_call_info *ci, struct rb_call_cache *cc)
  // ruby 2.7
  //   VALUE vm_call_cfunc(rb_execution_context_t *ec, rb_control_frame_t *reg_cfp, struct rb_calling_info *calling, struct rb_call_data *cd)
  // ruby 3.0
  //   VALUE vm_call_cfunc(rb_execution_context_t *ec, rb_control_frame_t *reg_cfp, struct rb_calling_info *calling) 
  return function (args) {
    try {
      let ec = args[0];
      let reg_cfp = args[1];
      log(">> vm_call_cfunc(_with_frame): reg_cfp: " + reg_cfp + ", ec->cfp: " + vm.native.rb_execution_context_struct__cfp(ec))

      /*
        // ruby 2.7
        const struct rb_call_info *ci = &cd->ci;
        const struct rb_call_cache *cc = &cd->cc;

        // ruby 3.0
        const struct rb_callinfo *ci = calling->ci;
        const struct rb_callcache *cc = calling->cc;

        // all
        VALUE val;
        const rb_callable_method_entry_t *me = cc->me; // ruby 2.6-2.7
        const rb_callable_method_entry_t *me = vm_cc_cme(cc); // ruby 3.0 // cc->cme_
        const rb_method_cfunc_t *cfunc = vm_method_cfunc_entry(me);
        int len = cfunc->argc;

        VALUE recv = calling->recv;
        VALUE block_handler = calling->block_handler;
        int argc = calling->argc;

        ...
        reg_cfp->sp -= argc + 1;
        val = (*cfunc->invoker)(cfunc->func, recv, argc, reg_cfp->sp + 1); //note(jtd): attach to cfunc->func here
      */

      let calling_p = args[2];
      let recv_p = vm.native.rb_calling_info__recv(calling_p);
      let recv = r.rb_inspect2(r.rb_obj_class(recv_p));
      let recv_inspect = r.rb_inspect2(recv_p);

      let original_id = "TKTK"
      let cfunc_func = "TKTK"
      let cfunc_argc = -42
      let cfunc_invoker = "TKTK"
      let cfunc_func_p = 0;

      let cc_p;
      switch (vm.ruby_version) {
        case 26: {
          cc_p = args[4];
          break;
        }
        case 27: {
          cc_p = vm.native.rb_call_data__cc(args[3]);
          break;
        }
        case 30:
        case 31:
        default: {
          cc_p = vm.native.rb_calling_info__cc(calling_p);
        }
      }

      if (cc_p != ptr(0)) {
        let me_p;
        switch (vm.ruby_version) {
          case 26:
          case 27: {
            me_p = vm.native.rb_call_cache__me(cc_p);
            break;
          }
          case 30:
          case 31:
          default: {
            me_p = vm.native.rb_callcache__cme_(cc_p);
          }
        }
    
        if (me_p != ptr(0)) {
          let def_p = vm.native.rb_callable_method_entry_t__def(me_p);
          if (def_p != ptr(0)) {
            cfunc_func_p = vm.native.rb_method_definition_struct__cfunc__func(def_p);
            cfunc_func = r.get_func_name(cfunc_func_p)
    
            let cfunc_invoker_p = vm.native.rb_method_definition_struct__cfunc__invoker(def_p);
            cfunc_invoker = r.get_func_name(cfunc_invoker_p)
    
            cfunc_argc = vm.native.rb_method_definition_struct__cfunc__argc(def_p)
    
            let original_id_p = vm.native.rb_method_definition_struct__original_id(def_p)
            if (original_id_p != ptr(0)) {
              original_id = r.rb_id2name(original_id_p).readUtf8String();
            }
          }
        }
      }

      let mid = "TKTK";
      let call_info_orig_argc = -42; //note: this is not used in vm_call_cfunc itself, but we need it

      let ci_p = ptr(0);
      switch (vm.ruby_version) {
        case 26: {
          ci_p = args[3];
          break;
        }
        case 27: {
          ci_p = vm.native.rb_call_data__ci(args[3]);
          break;
        }
        case 30:
        case 31:
        default: {
          ci_p = vm.native.rb_calling_info__ci(calling_p);
        }
      }

      if (ci_p != ptr(0)) {
        let mid_p = ptr(0);
        switch (vm.ruby_version) {
          case 26:
          case 27: {
            mid_p = vm.native.rb_call_info__mid(ci_p);
            call_info_orig_argc = vm.native.rb_call_info__orig_argc(ci_p);
            break;
          }
          case 30:
          case 31:
          default: {
            mid_p = vm.native.rb_callinfo__mid(ci_p);
            call_info_orig_argc = vm.native.rb_callinfo__argc(ci_p);
          }
        }
        if (mid_p != ptr(0)) {
          mid = r.rb_id2name(mid_p).readUtf8String();
        }
      }

      let log_msg = ">> vm_call_cfunc: (" + recv_inspect + ")." + mid;
      if (original_id != mid) {
        log_msg += "[orig: " + original_id + "]"
      }
      log_msg += " // cfunc.func: " + cfunc_func + "(argc: " + call_info_orig_argc;
      if (cfunc_argc != call_info_orig_argc) {
        log_msg += ", defined argc: " + cfunc_argc;
      }
      log_msg += "); cfunc.invoker: " + cfunc_invoker
      log(log_msg);

      // if (cfunc_func_p in hooks.cfunc_hooks) {
      //   return;
      // }

      if (!(cfunc_func_p in hooks.cfunc_hooks_metadatas)
          && !(cfunc_func_p in r.rb_define_method_metadatas)
          && !(cfunc_func_p in r.rb_define_module_function_metadatas)) {
        // log(">> hooking cfunc dynamically")

        let metadata = {
          // recv: {
          //   address: recv_p,
          //   name: recv,
          //   inspect: recv_inspect
          // },
          method: {
            mid: mid,
          //   original_id: original_id
          },
          cfunc: {
            func_p: cfunc_func_p,
            func_s: cfunc_func,
            def_argc: cfunc_argc, // actually the one used to register the cfunc
            rt_argc: call_info_orig_argc // runtime argc // note: seemingly not needed
          }
        };

        hooks.cfunc_hooks_metadatas[cfunc_func_p] = metadata
        hooks.hook_cfunc(metadata, /*true*/ false);
      }
    } catch(e) {
      log("Error [trace_vm_call_cfunc]: " + String(e))
    }
  }
}

function trace_rb_iterate0(args) {
  /*
  VALUE
  rb_iterate(VALUE (* it_proc)(VALUE), VALUE data1,
             rb_block_call_func_t bl_proc, VALUE data2)
  {
    return rb_iterate0(it_proc, data1,
                       bl_proc ? rb_vm_ifunc_proc_new(bl_proc, (void *)data2) : 0,
                       GET_EC());
  }

  VALUE
  rb_iterate0(VALUE (* it_proc) (VALUE), VALUE data1,
              const struct vm_ifunc *const ifunc,
              rb_execution_context_t *ec)
  */


  try {
    let it_proc_p = args[0]
    let data1_p = args[1]
    let ifunc_p = args[2]
    let func_p = null;
    let data2_p = null;
    let ec_p = args[3]

    let it_proc_str = r.get_func_name(it_proc_p)
    let data1_str;
    let func_str;
    let data2_str;

    if (it_proc_p.equals(r.iterate_method_addr)) {
      let obj = vm.native.iter_method_arg__obj(data1_p)
      let mid = vm.native.iter_method_arg__mid(data1_p)
      let argc = vm.native.iter_method_arg__argc(data1_p)
      let argv_p = vm.native.iter_method_arg__argv(data1_p)
      let kw_splat = vm.native.iter_method_arg__kw_splat(data1_p)

      let argv = []
      for (let i=0; i<argc; i++) {
        argv.push(r.rb_inspect2(argv_p.add(i*Process.pointerSize).readPointer()))
      }
      let argv_str = "[" + argv.join(", ") + "]"

      data1_str = "{ obj: " + r.rb_inspect2(obj) + ", mid: " + r.rb_id2name(mid).readUtf8String() + ", argv: " + argv_str + ", kw_splat: " + kw_splat + "}" 

      //data2_str = data2_p.toString()
    } else {
      data1_str = r.rb_inspect2(data1_p)
      //data2_str = r.rb_inspect2(data2_p)
    }

    if (ifunc_p.isNull()) {
      log(">> rb_iterate0(" + it_proc_str + ", " + data1_str + ", ifunc: NULL, ec: " + ec_p + ")")
      return
    }
    
    func_p = vm.native.vm_ifunc__func(ifunc_p)
    data2_p = vm.native.vm_ifunc__data(ifunc_p)

    func_str = r.get_func_name(func_p)
    data2_str = r.rb_inspect2(data2_p)

    log(">> rb_iterate0(" + it_proc_str + ", " + data1_str + ", ifunc: { func: " + func_str + ", data: " + data2_str + "}, ec: " + ec_p + ")")
  } catch(e) {
    console.error("Error [trace_rb_iterate0]: " + String(e))
  }
}

const ruby_tag_type = {
  0x0: "RUBY_TAG_NONE",
  0x1: "RUBY_TAG_RETURN",
  0x2: "RUBY_TAG_BREAK",
  0x3: "RUBY_TAG_NEXT",
  0x4: "RUBY_TAG_RETRY",
  0x5: "RUBY_TAG_REDO",
  0x6: "RUBY_TAG_RAISE",
  0x7: "RUBY_TAG_THROW",
  0x8: "RUBY_TAG_FATAL",
}
const RUBY_TAG_MASK = 0xf

function trace_rb_ec_tag_jump(sym_name) {
  /*
  NORETURN(static inline void rb_ec_tag_jump(const rb_execution_context_t *ec, enum ruby_tag_type st));
  static inline void
  rb_ec_tag_jump(const rb_execution_context_t *ec, enum ruby_tag_type st)
  */

  //note: it took absolutely forever to determine this, but this function has
  //      been mangled from partial inlining. instead of ec being passed as the
  //      first argument, ec->tag is. so we GET_EC directly.

  return function(args) {
    try {
      let tag_p = args[0]
      // let ec_p0 = args[0]
      let st = parseInt(args[1].and(RUBY_TAG_MASK).toString())
      let st_str = ruby_tag_type[st] || "unknown";

      let ec_p = vm.GET_EC()
      let errinfo_p = vm.native.rb_execution_context_struct__errinfo(ec_p);

      let mesg = null;
      let throwobj = null;
      let mesg_throwobj_str;
      // let val = null;
      // let val_str = null;

      let cause;
      let cause_str;

      if (r.RB_TYPE_P(errinfo_p, r.T_IMEMO)) {
        // log(">> rb_ec_tag_jump: errinfo is a T_IMEMO")
        throwobj = vm.native.vm_throw_data__throw_obj(errinfo_p)
        mesg_throwobj_str = r.rb_inspect2(throwobj)

        //note: this chain seemingly breaks w/ on the first instance of the
        //      hook, w/ the 2nd tt being 0x34. then on the following instance
        //      of the hook, it "succeeds" but with a retval equal to the tag
        // trawl ec->tag for val
        // struct rb_vm_tag *tt = ec->tag;
        // while (tt) {
        //     if (tt->tag == tag) {
        //         tt->retval = value;
        //         break;
        //     }
        //     tt = tt->prev;
        // }
        // let tt = vm.native.rb_execution_context_struct__tag(ec_p)
        // while (!tt.isNull()) {
        //   log(">> rb_ec_tag_jump 3: tt: " + tt)
        //   let tag = vm.native.rb_vm_tag__tag(tt)
        //   if (tag.equals(throwobj)) {
        //     val = vm.native.rb_vm_tag__retval(tt)
        //     try {
        //       val_str = r.rb_inspect2(val)
        //     } catch (e) {
        //       val_str = "<uninspectable>"
        //     }
        //     break;
        //   }
        //   tt = vm.native.rb_vm_tag__prev(tt)
        // }
        // if (val == null) {
        //   val_str = "<unknown>"
        // }
      } else {
        // log(">> errinfo is not a T_IMEMO")
        mesg = errinfo_p;
        mesg_throwobj_str = r.rb_inspect2(mesg)
      }

      if (mesg == null) {
        cause = r.rb_attr_get(throwobj, r.cause_sym)
      } else {
        cause = r.rb_attr_get(mesg, r.cause_sym)
      }

      if (!cause.isNull()) {
        cause_str = r.rb_inspect2(cause)
      } else {
        cause_str = "NULL"
      }

      if (throwobj != null) {
        // log(">> rb_ec_tag_jump: st: " + st_str + ", throwobj/tag: " + mesg_throwobj_str + ", val: " + val_str + ", cause: " + cause_str)
        log(">> rb_ec_tag_jump: st: " + st_str + ", throwobj/tag: " + mesg_throwobj_str + ", cause: " + cause_str)
      } else {
        log(">> rb_ec_tag_jump: st: " + st_str + ", mesg: " + mesg_throwobj_str + ", cause: " + cause_str)
      }


    } catch(e) {
      log("Error [trace_rb_ec_tag_jump: " + sym_name + "]: " + String(e))
    }
  }
}

function trace_rb_throw_obj(args) {
  //void
  //rb_throw_obj(VALUE tag, VALUE value)
  try {
    let tag = args[0]
    let value = args[1]

    // log(">> rb_throw_obj[raw](" + tag + ", " + value + ")")

    let tag_str = r.rb_inspect2(tag)
    let value_str = r.rb_inspect2(value)

    log(">> rb_throw_obj(" + tag_str + ", " + value_str + ")")
    // let rb_imemo_new_hook = Interceptor.attach(r.libruby.getExportByName('rb_imemo_new'), {
    //   onLeave: function(retval) {
    //     try {
    //       log(">> rb_imemo_new -> " + retval)
    //       let throw_obj = vm.native.vm_throw_data__throw_obj(retval)
    //       log(">> rb_imemo_new -> retval->throw_obj: " + r.rb_inspect2(throw_obj))
    //     } catch (e) {
    //       console.error("Error [rb_imemo_new]: " + String(e))
    //     } finally {
    //       rb_imemo_new_hook.detach()
    //     }
    //   }
    // })
  } catch(e) {
    log("Error [trace_rb_throw_obj]: " + String(e))
  }

}
